#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSN Sweep - scan text for possible Social Security Numbers and show the
surrounding characters for each hit.

Reads .txt, .csv, .tsv, .xlsx and .pdf. Detection lives in detector.py,
file parsing in extract.py.

Python 3.7+, standard library only. Nothing is sent off the machine.

Hardening notes
---------------
Binding to 127.0.0.1 is not by itself an access control. Any process or
user on the box can reach a loopback port, and a web page in your browser
can reach it too via DNS rebinding. So:

  * Host and Origin are pinned to loopback. A rebound hostname is refused.
  * Both scan endpoints require a per-run token, printed at startup and
    carried in a custom header. Custom headers cannot be set by a simple
    cross-origin form post, which kills CSRF, and a local process that
    never saw the console output does not have the token.
  * Responses carry a restrictive CSP and are marked no-store.
  * Sockets time out, so a half-open connection cannot pin a thread.

Usage
-----
  python ssn_scanner.py                      start the web UI on localhost:8000
  python ssn_scanner.py --port 8080          start on another port
  python ssn_scanner.py --file records.xlsx  scan from the command line instead
  python ssn_scanner.py --file r.txt --chars 80 --reveal
"""

import argparse
import hmac
import json
import os
import re
import secrets
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from detector import DEFAULT_CONTEXT_CHARS, excerpt, scan_text, summarize
from extract import ExtractionError, extract, locate

MAX_BYTES = 25 * 1024 * 1024
SOCKET_TIMEOUT = 20

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
if not os.path.isfile(os.path.join(STATIC_DIR, "index.html")):
    STATIC_DIR = BASE_DIR

ROUTES = {
    "/": ("index.html", "text/html"),
    "/index.html": ("index.html", "text/html"),
    "/style.css": ("style.css", "text/css"),
    "/app.js": ("app.js", "application/javascript"),
}

# 'none' by default; only what this page actually uses is allowed back in.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "connect-src 'self'; img-src 'none'; font-src 'none'; object-src 'none'; "
       "form-action 'none'; frame-ancestors 'none'; base-uri 'none'")


# ---------------------------------------------------------------------------
# shared
# ---------------------------------------------------------------------------

def analyze(data, filename, context_chars):
    """Extract, scan, and tag each finding with where it actually lives."""
    text, meta = extract(data, filename)
    findings = scan_text(text, context_chars)
    for f in findings:
        f["location"] = locate(meta, f["line"])
    return text, findings, meta


# ---------------------------------------------------------------------------
# command line mode
# ---------------------------------------------------------------------------

def run_cli(path, context_chars, reveal):
    if not os.path.isfile(path):
        print("No file at %s" % path, file=sys.stderr)
        return 2

    size = os.path.getsize(path)
    if size > MAX_BYTES:
        print("%s is %.1f MB, over the %d MB limit."
              % (path, size / 1048576.0, MAX_BYTES // 1048576), file=sys.stderr)
        return 2

    with open(path, "rb") as fh:
        data = fh.read()

    try:
        text, findings, meta = analyze(data, path, context_chars)
    except ExtractionError as exc:
        print("Could not read %s: %s" % (path, exc), file=sys.stderr)
        return 3

    counts = summarize(findings, text)

    print("=" * 78)
    print("SSN SWEEP  %s  [%s, %s]" % (path, meta["format"], meta["detail"]))
    print("%d candidate(s)   high %d   medium %d   low %d"
          % (counts["total"], counts["high"], counts["medium"], counts["low"]))
    print("=" * 78)

    for w in meta["warnings"]:
        print("  ! %s" % w)

    for f in findings:
        shown = f["value"] if reveal else f["masked"]
        near = ("   %d other SSN(s) in this window" % f["neighbors"]) if f["neighbors"] else ""
        tag = "  [ITIN]" if f["kind"] == "itin" else ""
        print("")
        print("[%03d] %s%s  score %+d  %s   %s, col %d%s"
              % (f["id"], f["confidence"].upper(), tag, f["score"], shown,
                 f["location"], f["column"], near))
        print("      why: %s" % "; ".join(f["reasons"]))
        print("      ...%s..." % excerpt(f, reveal))

    if counts["already_masked"]:
        print("\n%d value(s) in this file were already redacted by someone else."
              % counts["already_masked"])

    if not findings:
        print("\nNothing matched. The text has no 3-2-4 digit runs.")
    elif not reveal:
        print("\n(every number above is redacted; pass --reveal to print them)")
    return 0


# ---------------------------------------------------------------------------
# web server
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "SSNSweep"
    sys_version = ""                    # do not advertise the Python version
    protocol_version = "HTTP/1.0"
    timeout = SOCKET_TIMEOUT

    token = ""
    allowed_hosts = ()

    # -- plumbing ----------------------------------------------------------

    def _send(self, code, payload, ctype):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy",
                         "geolocation=(), camera=(), microphone=()")
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    # -- request gates -----------------------------------------------------

    def _host_ok(self):
        """Pin the Host header to loopback.

        A page on the internet can point a hostname it controls at 127.0.0.1
        and then talk to this server from inside the browser. The requests
        arrive with that attacker hostname in Host, so refusing anything
        that is not literally loopback shuts the technique down.
        """
        host = (self.headers.get("Host") or "").strip().lower()
        return host in self.allowed_hosts

    def _origin_ok(self):
        origin = (self.headers.get("Origin") or "").strip().lower()
        if not origin:
            return True                 # same-origin GETs send no Origin
        return any(origin == "http://" + h for h in self.allowed_hosts)

    def _token_ok(self):
        if not self.token:
            return True                 # --no-token
        sent = self.headers.get("X-Auth-Token") or ""
        return hmac.compare_digest(sent, self.token)

    def _guard(self):
        """Returns True when the request may proceed."""
        if not self._host_ok():
            self._json(403, {"error": "Refused: this server only answers to "
                                      "127.0.0.1 or localhost."})
            return False
        if not self._origin_ok():
            self._json(403, {"error": "Refused: cross-origin request."})
            return False
        return True

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            self._json(400, {"error": "Nothing was sent to scan."})
            return None
        if length > MAX_BYTES:
            self._json(413, {"error": "That file is over %d MB. Split it and "
                                      "scan the pieces." % (MAX_BYTES // 1048576)})
            return None
        data = self.rfile.read(length)
        if len(data) != length:
            self._json(400, {"error": "The upload was truncated."})
            return None
        return data

    def _respond(self, text, findings, meta, chars):
        self._json(200, {
            "findings": findings,
            "counts": summarize(findings, text),
            "context_chars": chars,
            "format": meta["format"],
            "detail": meta["detail"],
            "warnings": meta["warnings"],
        })

    # -- verbs -------------------------------------------------------------

    def do_OPTIONS(self):
        # No CORS. Refusing preflight is what keeps the custom auth header
        # unreachable from another origin.
        self._json(405, {"error": "Not allowed."})

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self._guard():
            return
        route = ROUTES.get(self.path.split("?", 1)[0])
        if route is None:
            self._send(404, "Not found", "text/plain")
            return
        filename, ctype = route
        try:
            with open(os.path.join(STATIC_DIR, filename), "rb") as fh:
                self._send(200, fh.read(), ctype)
        except IOError:
            self._send(500, "Missing %s." % filename, "text/plain")

    def do_POST(self):
        if not self._guard():
            return
        if not self._token_ok():
            self._json(403, {
                "error": "Missing or wrong access token. Open the exact URL "
                         "printed in the console window, including the ?t= part."})
            return

        if self.path == "/scan-file":
            self.handle_file()
        elif self.path == "/scan":
            self.handle_text()
        else:
            self._json(404, {"error": "Unknown endpoint."})

    # -- endpoints ---------------------------------------------------------

    def handle_text(self):
        raw = self._read_body()
        if raw is None:
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
            text = payload.get("text") or ""
            chars = int(payload.get("context_chars") or DEFAULT_CONTEXT_CHARS)
        except (ValueError, AttributeError):
            self._json(400, {"error": "The request was malformed."})
            return
        if not isinstance(text, str):
            self._json(400, {"error": "The request was malformed."})
            return

        chars = max(1, min(chars, 2000))
        try:
            text, findings, meta = analyze(text.encode("utf-8"), "pasted.txt", chars)
        except ExtractionError as exc:
            self._json(200, {"error": str(exc)})
            return
        self._respond(text, findings, meta, chars)

    def handle_file(self):
        """Raw bytes in the body, filename in a header. No multipart needed."""
        data = self._read_body()
        if data is None:
            return

        name = os.path.basename(self.headers.get("X-Filename") or "upload.txt")
        name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)[:120] or "upload.txt"
        try:
            chars = int(self.headers.get("X-Context-Chars") or DEFAULT_CONTEXT_CHARS)
        except ValueError:
            chars = DEFAULT_CONTEXT_CHARS
        chars = max(1, min(chars, 2000))

        try:
            text, findings, meta = analyze(data, name, chars)
        except ExtractionError as exc:
            self._json(200, {"error": str(exc)})
            return
        except Exception:
            # never surface a traceback to the page
            self._json(200, {"error": "That file could not be parsed. If it is "
                                      "a .xls or .doc, save it as .xlsx or "
                                      "export it to text first."})
            return

        self._respond(text, findings, meta, chars)

    # -- logging -----------------------------------------------------------

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))

    def log_error(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def handle_error(self, request, client_address):
        # default prints a traceback; say nothing useful to a prober
        sys.stderr.write("  dropped a malformed connection\n")


def run_server(port, open_browser, token):
    if not os.path.isfile(os.path.join(STATIC_DIR, "index.html")):
        print("index.html not found. Keep it in static/ or beside this script.",
              file=sys.stderr)
        return 2

    Handler.token = token
    Handler.allowed_hosts = ("127.0.0.1:%d" % port, "localhost:%d" % port)

    server = Server(("127.0.0.1", port), Handler)
    url = "http://127.0.0.1:%d/" % port
    if token:
        url += "?t=" + token

    print("SSN Sweep is up at:")
    print("  %s" % url)
    print("Loopback only, and the ?t= token is required. It changes every run.")
    print("Ctrl+C to stop.")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


def main():
    p = argparse.ArgumentParser(
        description="Scan text for possible Social Security Numbers.")
    p.add_argument("--file",
                   help="scan this file from the command line instead of starting the UI")
    p.add_argument("--chars", type=int, default=DEFAULT_CONTEXT_CHARS,
                   help="characters of context on each side (default 30)")
    p.add_argument("--reveal", action="store_true",
                   help="print full numbers instead of redacting them")
    p.add_argument("--port", type=int, default=8000,
                   help="port for the web UI (default 8000)")
    p.add_argument("--no-browser", action="store_true",
                   help="do not open a browser window")
    p.add_argument("--token", help="use this access token instead of a random one")
    p.add_argument("--no-token", action="store_true",
                   help="disable the access token (any local process can then scan)")
    args = p.parse_args()

    try:
        if args.file:
            return run_cli(args.file, max(1, args.chars), args.reveal)
        token = "" if args.no_token else (args.token or secrets.token_urlsafe(24))
        return run_server(args.port, not args.no_browser, token)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
