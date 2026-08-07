#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSN Sweep - scan text for possible Social Security Numbers and show the
surrounding words for each hit.

This file is the entry point: run a scan from the command line, or serve the
UI in static/ on loopback. Detection lives in detector.py.

Python 3.7+, standard library only. Nothing is sent off the machine.

Usage
-----
  python ssn_scanner.py                      start the web UI on localhost:8000
  python ssn_scanner.py --port 8080          start on another port
  python ssn_scanner.py --file records.txt   scan from the command line instead
  python ssn_scanner.py --file r.txt --words 50 --reveal
"""

import argparse
import json
import os
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from detector import DEFAULT_CONTEXT_WORDS, excerpt, scan_text, summarize

MAX_BYTES = 25 * 1024 * 1024          # refuse absurd payloads

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Front end lives in static/. Flat next to this script also works.
STATIC_DIR = os.path.join(BASE_DIR, "static")
if not os.path.isfile(os.path.join(STATIC_DIR, "index.html")):
    STATIC_DIR = BASE_DIR

# Explicit whitelist, so there is no path to traverse.
ROUTES = {
    "/": ("index.html", "text/html"),
    "/index.html": ("index.html", "text/html"),
    "/style.css": ("style.css", "text/css"),
    "/app.js": ("app.js", "application/javascript"),
}


# ---------------------------------------------------------------------------
# command line mode
# ---------------------------------------------------------------------------

def run_cli(path, context_words, reveal):
    if not os.path.isfile(path):
        print("No file at %s" % path, file=sys.stderr)
        return 2

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    findings = scan_text(text, context_words)
    counts = summarize(findings)

    print("=" * 78)
    print("SSN SWEEP  %s" % path)
    print("%d candidate(s)   high %d   medium %d   low %d"
          % (counts["total"], counts["high"], counts["medium"], counts["low"]))
    print("=" * 78)

    for f in findings:
        shown = f["value"] if reveal else f["masked"]
        near = ("   %d other SSN(s) in this window" % f["neighbors"]) if f["neighbors"] else ""
        print("")
        print("[%03d] %s   %s   line %d, col %d%s"
              % (f["id"], f["confidence"].upper(), shown, f["line"], f["column"], near))
        print("      why: %s" % "; ".join(f["reasons"]))
        print("      ...%s..." % excerpt(f, reveal))

    if not findings:
        print("\nNothing matched. The text has no 3-2-4 digit runs.")
    elif not reveal:
        print("\n(every number above is redacted; pass --reveal to print them)")
    return 0


# ---------------------------------------------------------------------------
# web server
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "SSNSweep/2.0"

    def _send(self, code, payload, ctype):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        route = ROUTES.get(self.path.split("?", 1)[0])
        if route is None:
            self._send(404, "Not found", "text/plain")
            return

        filename, ctype = route
        try:
            with open(os.path.join(STATIC_DIR, filename), "rb") as fh:
                self._send(200, fh.read(), ctype)
        except IOError:
            self._send(500, "Missing %s. Keep it in static/ or beside "
                            "ssn_scanner.py." % filename, "text/plain")

    def do_POST(self):
        if self.path != "/scan":
            self._send(404, json.dumps({"error": "Unknown endpoint."}),
                       "application/json")
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0

        if length <= 0:
            self._send(400, json.dumps({"error": "Nothing was sent to scan."}),
                       "application/json")
            return
        if length > MAX_BYTES:
            self._send(413, json.dumps({
                "error": "That file is over %d MB. Split it and scan the pieces."
                         % (MAX_BYTES // (1024 * 1024))}), "application/json")
            return

        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
            text = payload.get("text") or ""
            words = int(payload.get("context_words") or DEFAULT_CONTEXT_WORDS)
        except (ValueError, AttributeError):
            self._send(400, json.dumps({"error": "The request was malformed."}),
                       "application/json")
            return

        words = max(1, min(words, 200))
        findings = scan_text(text, words)
        self._send(200, json.dumps({
            "findings": findings,
            "counts": summarize(findings),
            "context_words": words,
        }), "application/json")

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))


def run_server(port, open_browser):
    if not os.path.isfile(os.path.join(STATIC_DIR, "index.html")):
        print("index.html not found. Keep it in static/ or beside this script.",
              file=sys.stderr)
        return 2

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = "http://127.0.0.1:%d/" % port
    print("SSN Sweep is up at %s" % url)
    print("Bound to loopback only. Ctrl+C to stop.")
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
    p.add_argument("--words", type=int, default=DEFAULT_CONTEXT_WORDS,
                   help="words of context on each side (default 30)")
    p.add_argument("--reveal", action="store_true",
                   help="print full numbers instead of redacting them")
    p.add_argument("--port", type=int, default=8000,
                   help="port for the web UI (default 8000)")
    p.add_argument("--no-browser", action="store_true",
                   help="do not open a browser window")
    args = p.parse_args()

    try:
        if args.file:
            return run_cli(args.file, max(1, args.words), args.reveal)
        return run_server(args.port, not args.no_browser)
    except BrokenPipeError:      # piping into head/more closed the stream
        return 0


if __name__ == "__main__":
    sys.exit(main())
