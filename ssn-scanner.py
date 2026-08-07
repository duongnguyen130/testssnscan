#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSN Sweep - scan text files for possible Social Security Numbers and show
30 words of context on either side of every hit.

Python 3.7+, standard library only. Nothing is sent off the machine.

Usage
-----
  python ssn_scanner.py                      start the web UI on localhost:8000
  python ssn_scanner.py --port 8080          start on another port
  python ssn_scanner.py --file records.txt   scan from the command line instead
  python ssn_scanner.py --file r.txt --words 50 --reveal
"""

import argparse
import bisect
import json
import os
import re
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BYTES = 25 * 1024 * 1024          # refuse absurd payloads
DEFAULT_CONTEXT_WORDS = 30
KEYWORD_WINDOW = 60                    # chars either side to look for a label

# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------

# 3-2-4 digits with an optional single dash or space between each group.
# Guarded so we do not chew a slice out of a longer digit run.
SSN_PATTERN = re.compile(
    r"(?<![0-9\-])"
    r"([0-9]{3})([- ]?)([0-9]{2})([- ]?)([0-9]{4})"
    r"(?![0-9\-])"
)

# Labels that make a nearby number far more likely to really be an SSN.
KEYWORD_PATTERN = re.compile(
    r"(ssn|ss\s*#|s\.s\.|social\s*security|socsec|taxpayer\s*id|\btin\b|\bitin\b"
    r"|so\s*bao\s*hiem\s*xa\s*hoi)",
    re.IGNORECASE,
)

WORD_PATTERN = re.compile(r"\S+")

PLACEHOLDERS = {
    "123456789", "987654321", "111111111", "222222222", "333333333",
    "444444444", "555555555", "666666666", "777777777", "888888888",
    "999999999", "000000000", "078051120", "219099999", "457555462",
}


def _structural_problems(area, group, serial):
    """SSA allocation rules. Returns a list of human-readable reasons."""
    problems = []
    if area == "000":
        problems.append("area 000 is never issued")
    elif area == "666":
        problems.append("area 666 is never issued")
    elif area[0] == "9":
        problems.append("area 900-999 is never issued")
    if group == "00":
        problems.append("group 00 is never issued")
    if serial == "0000":
        problems.append("serial 0000 is never issued")
    return problems


def _score(sep, has_keyword, problems, digits):
    """Turn the signals into HIGH / MEDIUM / LOW plus the reasons why."""
    points = 0
    reasons = []

    if sep == "-":
        points += 4
        reasons.append("written in 3-2-4 dashed form")
    elif sep == " ":
        points += 3
        reasons.append("written in 3-2-4 spaced form")
    else:
        reasons.append("bare 9-digit run, no separators")

    if has_keyword:
        points += 3
        reasons.append("an SSN label appears nearby")

    if problems:
        points -= 4
        reasons.extend(problems)
    else:
        points += 1

    if digits in PLACEHOLDERS:
        points -= 2
        reasons.append("well-known test or placeholder value")

    if points >= 5:
        level = "high"
    elif points >= 3:
        level = "medium"
    else:
        level = "low"
    return level, points, reasons


def _squash(s):
    """Collapse whitespace runs so a snippet reads as one flowing line."""
    return re.sub(r"\s+", " ", s).strip()


def scan_text(text, context_words=DEFAULT_CONTEXT_WORDS):
    """Find every candidate SSN and return it with surrounding word context."""
    words = [(m.start(), m.end()) for m in WORD_PATTERN.finditer(text)]
    word_starts = [w[0] for w in words]
    findings = []

    for m in SSN_PATTERN.finditer(text):
        area, sep1, group, sep2, serial = m.groups()

        # "123-45 6789" is a coincidence, not a formatted SSN.
        if sep1 != sep2:
            continue

        digits = area + group + serial
        start, end = m.start(), m.end()

        window = text[max(0, start - KEYWORD_WINDOW):end + KEYWORD_WINDOW]
        has_keyword = bool(KEYWORD_PATTERN.search(window))

        problems = _structural_problems(area, group, serial)
        level, points, reasons = _score(sep1, has_keyword, problems, digits)

        # word-based context
        i = max(bisect.bisect_right(word_starts, start) - 1, 0)
        j = max(bisect.bisect_right(word_starts, end - 1) - 1, 0)
        before = words[max(0, i - context_words):i]
        after = words[j + 1:j + 1 + context_words]

        before_text = text[before[0][0]:start] if before else text[words[i][0]:start] if words else ""
        after_text = text[end:after[-1][1]] if after else text[end:words[j][1]] if words else ""

        last_nl = text.rfind("\n", 0, start)
        line = text.count("\n", 0, start) + 1
        column = start - last_nl

        findings.append({
            "id": len(findings) + 1,
            "value": m.group(0),
            "digits": digits,
            "masked": "***-**-" + serial,
            "last4": serial,
            "offset": start,
            "line": line,
            "column": column,
            "confidence": level,
            "score": points,
            "reasons": reasons,
            "labeled": has_keyword,
            "valid_structure": not problems,
            "before": _squash(before_text),
            "after": _squash(after_text),
            "words_before": len(before),
            "words_after": len(after),
            "truncated_start": bool(before) and before[0][0] == words[0][0] and i - context_words <= 0,
            "truncated_end": bool(after) and after[-1][1] == words[-1][1],
        })

    return findings


def summarize(findings):
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["confidence"]] += 1
    counts["total"] = len(findings)
    return counts


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
        print("")
        print("[%03d] %s   %s   line %d, col %d"
              % (f["id"], f["confidence"].upper(), shown, f["line"], f["column"]))
        print("      why: %s" % "; ".join(f["reasons"]))
        print("      ...%s  >>%s<<  %s..." % (f["before"], shown, f["after"]))

    if not findings:
        print("\nNothing matched. The file has no 3-2-4 digit runs.")
    elif not reveal:
        print("\n(values masked; pass --reveal to print them in full)")
    return 0


# ---------------------------------------------------------------------------
# web ui
# ---------------------------------------------------------------------------

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSN Sweep</title>
<style>
  :root {
    --stock:  #EEF0E9;
    --panel:  #F8F9F5;
    --ink:    #16211C;
    --ink-2:  #55665C;
    --rule:   #BAC5B7;
    --stamp:  #A8271C;
    --marker: #F4E85C;
    --display: "Arial Narrow", "Helvetica Neue Condensed", "Liberation Sans Narrow", "Nimbus Sans Narrow", sans-serif;
    --mono: ui-monospace, "SF Mono", "Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace;
    --ui: "Segoe UI", system-ui, -apple-system, sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--stock);
    color: var(--ink);
    font-family: var(--ui);
    font-size: 15px;
    line-height: 1.5;
  }
  .wrap { max-width: 940px; margin: 0 auto; padding: 0 20px 80px; }

  /* header reads like the top of a filed form */
  header {
    border-bottom: 3px double var(--ink);
    margin-bottom: 28px;
    padding: 26px 0 12px;
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }
  h1 {
    font-family: var(--display);
    font-size: 42px;
    letter-spacing: .14em;
    text-transform: uppercase;
    font-weight: 700;
    margin: 0;
  }
  .stamp-note {
    font-size: 11px;
    letter-spacing: .16em;
    text-transform: uppercase;
    color: var(--stamp);
    border: 1.5px solid var(--stamp);
    padding: 5px 9px;
    transform: rotate(-1.5deg);
  }

  .panel {
    background: var(--panel);
    border: 1px solid var(--rule);
    padding: 20px;
  }
  .field-label {
    font-size: 11px;
    letter-spacing: .18em;
    text-transform: uppercase;
    color: var(--ink-2);
    display: block;
    margin-bottom: 8px;
  }
  .drop {
    border: 1.5px dashed var(--rule);
    padding: 22px;
    text-align: center;
    background: transparent;
    transition: border-color .15s, background .15s;
  }
  .drop.hot { border-color: var(--stamp); background: rgba(168,39,28,.05); }
  .drop p { margin: 6px 0 0; color: var(--ink-2); font-size: 13px; }
  textarea {
    width: 100%;
    min-height: 130px;
    resize: vertical;
    font-family: var(--mono);
    font-size: 13px;
    line-height: 1.6;
    color: var(--ink);
    background: repeating-linear-gradient(
      var(--panel), var(--panel) 19.6px, var(--rule) 19.6px, var(--rule) 20.8px);
    border: 1px solid var(--rule);
    padding: 10px 12px;
  }
  .row { display: flex; gap: 18px; align-items: flex-end; flex-wrap: wrap; margin-top: 18px; }
  .row > div { flex: 0 0 auto; }
  input[type=number] {
    width: 84px; padding: 8px 10px; font-family: var(--mono); font-size: 14px;
    border: 1px solid var(--rule); background: #fff; color: var(--ink);
  }
  button {
    font-family: var(--ui); font-size: 13px; letter-spacing: .1em;
    text-transform: uppercase; cursor: pointer;
    border: 1px solid var(--ink); background: transparent; color: var(--ink);
    padding: 9px 16px;
  }
  button:hover { background: var(--ink); color: var(--panel); }
  button.primary { background: var(--stamp); border-color: var(--stamp); color: #fff; }
  button.primary:hover { background: #8b1f16; border-color: #8b1f16; }
  button[disabled] { opacity: .4; cursor: not-allowed; }
  button:focus-visible, textarea:focus-visible, input:focus-visible, .hit:focus-visible {
    outline: 2px solid var(--stamp); outline-offset: 2px;
  }
  .hint { margin-left: auto; font-size: 12px; color: var(--ink-2); align-self: center; }

  /* tally */
  .tally {
    display: flex; gap: 26px; flex-wrap: wrap; align-items: baseline;
    margin: 34px 0 14px; padding-bottom: 12px; border-bottom: 1px solid var(--rule);
  }
  .tally b { font-family: var(--display); font-size: 30px; letter-spacing: .05em; }
  .tally span { font-size: 11px; letter-spacing: .16em; text-transform: uppercase; color: var(--ink-2); margin-left: 7px; }
  .tally .hi b { color: var(--stamp); }

  .toolbar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 20px; }
  .chip {
    font-size: 11px; letter-spacing: .12em; text-transform: uppercase;
    padding: 6px 12px; border: 1px solid var(--rule); background: transparent;
  }
  .chip[aria-pressed="true"] { background: var(--ink); color: var(--panel); border-color: var(--ink); }
  .toolbar .right { margin-left: auto; display: flex; gap: 8px; }

  /* a finding is a strip clipped out of the document */
  .find {
    display: grid; grid-template-columns: 92px 1fr;
    border: 1px solid var(--rule); border-left: 4px solid var(--rule);
    background: var(--panel); margin-bottom: 14px;
  }
  .find.high { border-left-color: var(--stamp); }
  .find.medium { border-left-color: #C99A2E; }
  .gutter {
    padding: 14px 12px; border-right: 1px solid var(--rule);
    font-family: var(--mono); font-size: 11px; color: var(--ink-2); line-height: 1.7;
  }
  .gutter .lvl {
    display: block; font-family: var(--ui); font-size: 10px; letter-spacing: .14em;
    text-transform: uppercase; margin-bottom: 6px; color: var(--ink);
  }
  .find.high .gutter .lvl { color: var(--stamp); font-weight: 700; }
  .body { padding: 14px 16px; }
  .excerpt { font-family: var(--mono); font-size: 13.5px; line-height: 1.75; word-break: break-word; }
  .excerpt .ell { color: var(--ink-2); }
  .why { margin-top: 10px; font-size: 12px; color: var(--ink-2); }

  /* signature: the redaction bar you peel back */
  .hit {
    position: relative; display: inline-block; padding: 1px 3px;
    font-weight: 700; cursor: pointer; border: 0; background: transparent;
    font-family: var(--mono); font-size: 13.5px; color: var(--ink);
  }
  .hit::before {
    content: ""; position: absolute; inset: 0; background: var(--marker);
    transform: scaleX(0); transform-origin: left; z-index: -1;
    animation: sweep .32s ease-out forwards; animation-delay: var(--d, 0s);
  }
  @keyframes sweep { to { transform: scaleX(1); } }
  .hit .bar {
    display: inline-block; background: var(--ink); color: transparent;
    border-radius: 1px; user-select: none;
  }
  @media (prefers-reduced-motion: reduce) {
    .hit::before { animation: none; transform: scaleX(1); }
  }

  .empty { padding: 40px 20px; text-align: center; color: var(--ink-2); border: 1px dashed var(--rule); }
  .empty strong { display: block; font-family: var(--display); font-size: 22px;
    letter-spacing: .12em; text-transform: uppercase; color: var(--ink); margin-bottom: 6px; }
  .err { border-left: 4px solid var(--stamp); padding: 12px 16px; background: rgba(168,39,28,.06); font-size: 14px; }
  label.inline { font-size: 12px; color: var(--ink-2); display: flex; align-items: center; gap: 6px; cursor: pointer; }
  @media (max-width: 620px) {
    h1 { font-size: 30px; }
    .find { grid-template-columns: 1fr; }
    .gutter { border-right: 0; border-bottom: 1px solid var(--rule); }
  }
</style>
</head>
<body>
<div class="wrap">

  <header>
    <h1>SSN Sweep</h1>
    <div class="stamp-note">Runs on this machine only</div>
  </header>

  <div class="panel" id="drop">
    <span class="field-label">Text to scan</span>
    <div class="drop" id="dropzone">
      <button type="button" id="pick">Choose a .txt file</button>
      <p>or drop one here</p>
      <input type="file" id="file" accept=".txt,.log,.csv,text/plain" hidden>
    </div>
    <div style="margin-top:16px">
      <span class="field-label">Or paste it</span>
      <textarea id="text" spellcheck="false" placeholder="Paste the contents here."></textarea>
    </div>
    <div class="row">
      <div>
        <span class="field-label">Words of context</span>
        <input type="number" id="words" value="30" min="1" max="200">
      </div>
      <div><button class="primary" id="scan">Scan</button></div>
      <div><button id="clear">Clear</button></div>
      <div class="hint" id="loaded"></div>
    </div>
  </div>

  <div id="out"></div>
</div>

<script>
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var state = { findings: [], filter: "all", revealed: {}, revealAll: false, name: "pasted text" };

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  /* file intake */
  $("pick").addEventListener("click", function () { $("file").click(); });
  $("file").addEventListener("change", function (e) { load(e.target.files[0]); });

  var dz = $("dropzone");
  ["dragenter", "dragover"].forEach(function (n) {
    dz.addEventListener(n, function (e) { e.preventDefault(); dz.classList.add("hot"); });
  });
  ["dragleave", "drop"].forEach(function (n) {
    dz.addEventListener(n, function (e) { e.preventDefault(); dz.classList.remove("hot"); });
  });
  dz.addEventListener("drop", function (e) {
    if (e.dataTransfer.files.length) { load(e.dataTransfer.files[0]); }
  });

  function load(f) {
    if (!f) { return; }
    var r = new FileReader();
    r.onload = function () {
      $("text").value = r.result;
      state.name = f.name;
      $("loaded").textContent = f.name + " loaded, " + r.result.length.toLocaleString() + " characters";
    };
    r.onerror = function () { fail("That file could not be read. Try a plain text file."); };
    r.readAsText(f);
  }

  $("clear").addEventListener("click", function () {
    $("text").value = ""; $("file").value = ""; $("loaded").textContent = "";
    state.findings = []; state.name = "pasted text"; $("out").innerHTML = "";
  });

  /* scan */
  $("scan").addEventListener("click", function () {
    var text = $("text").value;
    if (!text.trim()) { fail("Add a file or paste some text first."); return; }
    var n = parseInt($("words").value, 10);
    if (isNaN(n) || n < 1) { n = 30; $("words").value = 30; }

    $("scan").disabled = true;
    $("scan").textContent = "Scanning";
    fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text, context_words: n })
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.error) { fail(d.error); return; }
        state.findings = d.findings;
        state.revealed = {};
        state.revealAll = false;
        render(d.counts);
      })
      .catch(function () { fail("The scanner did not answer. Is the server still running?"); })
      .finally(function () { $("scan").disabled = false; $("scan").textContent = "Scan"; });
  });

  function fail(msg) { $("out").innerHTML = '<div class="err">' + esc(msg) + "</div>"; }

  /* render */
  function render(counts) {
    var out = $("out");
    if (!counts.total) {
      out.innerHTML = '<div class="empty"><strong>Clean</strong>' +
        "No 3-2-4 digit run turned up in " + esc(state.name) + ".</div>";
      return;
    }

    var h = '<div class="tally">' +
      '<div><b>' + counts.total + "</b><span>candidates</span></div>" +
      '<div class="hi"><b>' + counts.high + "</b><span>high</span></div>" +
      "<div><b>" + counts.medium + "</b><span>medium</span></div>" +
      "<div><b>" + counts.low + "</b><span>low</span></div>" +
      "</div>";

    h += '<div class="toolbar">';
    ["all", "high", "medium", "low"].forEach(function (f) {
      h += '<button class="chip" data-filter="' + f + '" aria-pressed="' +
        (state.filter === f) + '">' + f + "</button>";
    });
    h += '<div class="right">' +
      '<button id="reveal">' + (state.revealAll ? "Hide values" : "Reveal values") + "</button>" +
      '<button id="csv">Export CSV</button>' +
      '<button id="json">Export JSON</button>' +
      "</div></div>";

    h += '<label class="inline" style="margin:-10px 0 18px">' +
      '<input type="checkbox" id="unmasked"> Put full numbers in the export file</label>';

    var shown = state.findings.filter(function (f) {
      return state.filter === "all" || f.confidence === state.filter;
    });

    shown.forEach(function (f, i) {
      var open = state.revealAll || state.revealed[f.id];
      var val = open
        ? esc(f.value)
        : '<span class="bar">' + "&nbsp;".repeat(6) + "</span>" + esc(f.last4);
      h += '<div class="find ' + f.confidence + '">' +
        '<div class="gutter"><span class="lvl">' + f.confidence + "</span>" +
        "L" + f.line + "<br>col " + f.column + "<br>@" + f.offset + "</div>" +
        '<div class="body"><div class="excerpt">' +
        (f.words_before ? '<span class="ell">&hellip;</span> ' : "") +
        esc(f.before) + " " +
        '<button class="hit" data-id="' + f.id + '" style="--d:' + (i * 0.035) + 's" ' +
        'title="' + (open ? "Hide this number" : "Show this number") + '">' + val + "</button> " +
        esc(f.after) +
        (f.words_after ? ' <span class="ell">&hellip;</span>' : "") +
        "</div>" +
        '<div class="why">' + esc(f.reasons.join(" \\u00b7 ")) + "</div>" +
        "</div></div>";
    });

    if (!shown.length) {
      h += '<div class="empty"><strong>Nothing at this level</strong>Pick another filter above.</div>';
    }

    out.innerHTML = h;
    wire(counts);
  }

  function wire(counts) {
    Array.prototype.forEach.call(document.querySelectorAll(".chip"), function (b) {
      b.addEventListener("click", function () { state.filter = b.dataset.filter; render(counts); });
    });
    Array.prototype.forEach.call(document.querySelectorAll(".hit"), function (b) {
      b.addEventListener("click", function () {
        var id = b.dataset.id;
        state.revealed[id] = !state.revealed[id];
        render(counts);
      });
    });
    $("reveal").addEventListener("click", function () {
      state.revealAll = !state.revealAll; render(counts);
    });
    $("csv").addEventListener("click", function () { download("csv"); });
    $("json").addEventListener("click", function () { download("json"); });
  }

  function download(kind) {
    var full = $("unmasked") && $("unmasked").checked;
    var rows = state.findings.map(function (f) {
      return {
        id: f.id, confidence: f.confidence, value: full ? f.value : f.masked,
        line: f.line, column: f.column, offset: f.offset,
        reasons: f.reasons.join("; "), before: f.before, after: f.after
      };
    });
    var blob, name;
    if (kind === "json") {
      blob = new Blob([JSON.stringify({ source: state.name, findings: rows }, null, 2)],
        { type: "application/json" });
      name = "ssn-sweep.json";
    } else {
      var cols = ["id", "confidence", "value", "line", "column", "offset", "reasons", "before", "after"];
      var lines = [cols.join(",")];
      rows.forEach(function (r) {
        lines.push(cols.map(function (c) {
          return '"' + String(r[c]).replace(/"/g, '""') + '"';
        }).join(","));
      });
      blob = new Blob([lines.join("\\n")], { type: "text/csv" });
      name = "ssn-sweep.csv";
    }
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }
})();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "SSNSweep/1.0"

    def _send(self, code, body, ctype):
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html")
        else:
            self._send(404, "Not found", "text/plain")

    def do_POST(self):
        if self.path != "/scan":
            self._send(404, json.dumps({"error": "Unknown endpoint."}), "application/json")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            self._send(400, json.dumps({"error": "Nothing was sent to scan."}), "application/json")
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
            self._send(400, json.dumps({"error": "The request was malformed."}), "application/json")
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


def main():
    p = argparse.ArgumentParser(description="Scan text for possible Social Security Numbers.")
    p.add_argument("--file", help="scan this file from the command line instead of starting the UI")
    p.add_argument("--words", type=int, default=DEFAULT_CONTEXT_WORDS,
                   help="words of context on each side (default 30)")
    p.add_argument("--reveal", action="store_true", help="print full numbers instead of masking them")
    p.add_argument("--port", type=int, default=8000, help="port for the web UI (default 8000)")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    args = p.parse_args()

    if args.file:
        return run_cli(args.file, max(1, args.words), args.reveal)
    run_server(args.port, not args.no_browser)
    return 0


if __name__ == "__main__":
    sys.exit(main())
