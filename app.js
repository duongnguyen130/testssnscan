/* SSN Sweep - front end.
   Posts to /scan and renders findings. Every SSN in an excerpt is covered,
   not just the focal one, so a card is safe to screenshot as-is. */

(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  // Per-run token from the URL the server printed. Sent as a custom header:
  // a cross-origin page cannot set one without a preflight, and the server
  // refuses preflight, so this doubles as the CSRF defence.
  var TOKEN = (/[?&]t=([^&#]+)/.exec(location.search) || [])[1] || "";

  var IDLE_WIPE_MS = 10 * 60 * 1000;   // clear findings after this much quiet
  var idleTimer = null;

  var state = {
    findings: [],
    counts: null,
    filter: "all",
    revealed: {},     // per-card override, keyed by finding id
    revealAll: false,
    name: "pasted text"
  };

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  function fail(msg) {
    $("out").innerHTML = '<div class="err">' + esc(msg) + "</div>";
  }

  /* Drop every copy this page is holding: the parsed findings, the pasted
     text, the file handle, and the rendered DOM. Called on demand, when the
     page is left, and after a quiet spell. */
  function wipe(note) {
    state.findings = [];
    state.counts = null;
    state.warnings = [];
    state.revealed = {};
    state.revealAll = false;
    state.file = null;
    state.name = "pasted text";
    state.format = null;
    state.detail = null;

    $("text").value = "";
    $("file").value = "";
    $("loaded").textContent = "";
    $("text").placeholder = "Paste the contents here.";
    $("out").innerHTML = note
      ? '<div class="empty"><strong>Cleared</strong><span>' + esc(note) +
        "</span></div>"
      : "";
  }

  function touchIdle() {
    if (idleTimer) { clearTimeout(idleTimer); }
    idleTimer = setTimeout(function () {
      if (state.findings.length) {
        wipe("Results were cleared after 10 minutes without activity.");
      }
    }, IDLE_WIPE_MS);
  }

  ["click", "keydown", "scroll"].forEach(function (evt) {
    document.addEventListener(evt, touchIdle, { passive: true });
  });

  // leaving the page drops everything; nothing survives a reload
  window.addEventListener("pagehide", function () { wipe(); });

  /* ------------------------------------------------------------------ *
   * intake
   * ------------------------------------------------------------------ */

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

  var BINARY = /\.(xlsx|xlsm|xltx|pdf)$/i;

  function load(f) {
    if (!f) { return; }
    state.name = f.name;
    state.file = f;
    $("loaded").textContent = f.name + " \u00b7 " +
      Math.round(f.size / 1024).toLocaleString() + " KB";

    if (BINARY.test(f.name)) {
      // spreadsheets and PDFs are parsed server side; nothing to preview
      $("text").value = "";
      $("text").placeholder = f.name + " will be parsed when you press Scan.";
      return;
    }
    var r = new FileReader();
    r.onload = function () { $("text").value = r.result; };
    r.onerror = function () { fail("That file could not be read."); };
    r.readAsText(f);
  }

  $("clear").addEventListener("click", function () { wipe(); });

  /* ------------------------------------------------------------------ *
   * scan
   * ------------------------------------------------------------------ */

  $("scan").addEventListener("click", function () {
    var text = $("text").value;
    var binary = state.file && BINARY.test(state.file.name);
    if (!binary && !text.trim()) {
      fail("Add a file or paste some text first.");
      return;
    }

    var n = parseInt($("chars").value, 10);
    if (isNaN(n) || n < 1) { n = 30; $("chars").value = 30; }

    var btn = $("scan");
    btn.disabled = true;
    btn.textContent = "Scanning\u2026";

    var request = binary
      ? fetch("/scan-file", {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
            "X-Auth-Token": TOKEN,
            "X-Filename": state.file.name,
            "X-Context-Chars": String(n)
          },
          body: state.file
        })
      : fetch("/scan", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Auth-Token": TOKEN
          },
          body: JSON.stringify({ text: text, context_chars: n })
        });

    request
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.error) { fail(d.error); return; }
        state.findings = d.findings;
        state.counts = d.counts;
        state.format = d.format;
        state.detail = d.detail;
        state.warnings = d.warnings || [];
        state.revealed = {};
        state.revealAll = false;
        // the source text is no longer needed; the findings carry the context
        $("text").value = "";
        touchIdle();
        render();
      })
      .catch(function () {
        fail("The scanner did not answer. Is the server still running?");
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = "Scan";
      });
  });

  /* ------------------------------------------------------------------ *
   * render
   * ------------------------------------------------------------------ */

  /* One SSN inside an excerpt. Covered digits become a solid block sized
     to how many characters it hides, so nothing is inferable from width. */
  function hit(value, last4, opts) {
    var open = opts.open;
    var cls = "hit" + (opts.focal ? " focal" : "") + (open ? " open" : "");
    var label = open ? "Hide this number" : "Show this number";
    var inner;

    if (open) {
      inner = esc(value);
    } else {
      var hidden = Math.max(value.length - 4, 1);
      inner = '<span class="cover" style="width:' + hidden + "ch;--d:" +
        (opts.delay || 0) + 's"></span>' + esc(last4);
    }

    return '<button class="' + cls + '" data-id="' + opts.id + '" title="' +
      label + '" aria-label="' + label + '">' + inner + "</button>";
  }

  /* Excerpt side: text segments plus every neighbouring SSN, all covered. */
  function side(segments, id, open, delay) {
    return segments.map(function (s) {
      if (s.kind === "text") { return esc(s.text); }
      return hit(s.text, s.last4, { id: id, open: open, focal: false, delay: delay });
    }).join("");
  }

  function render() {
    var out = $("out");
    var counts = state.counts;

    if (!counts || !counts.total) {
      out.innerHTML = '<div class="empty"><strong>Nothing found</strong>' +
        "<span>No 3-2-4 digit run turned up in " + esc(state.name) +
        ".</span></div>";
      return;
    }

    var h = '<section class="results">';

    h += '<div class="stats">' +
      '<div class="stat"><b>' + counts.total + "</b><span>candidates</span></div>" +
      '<div class="stat is-high"><b>' + counts.high + "</b><span>high</span></div>" +
      '<div class="stat is-medium"><b>' + counts.medium + "</b><span>medium</span></div>" +
      '<div class="stat"><b>' + counts.low + "</b><span>low</span></div>" +
      "</div>";

    if (state.revealAll) {
      h += '<div class="notice"><span aria-hidden="true">\u25CF</span><div>' +
        "<b>Values are visible.</b> They are also in anything you copy or " +
        "export while this is on, and the Windows clipboard keeps a history." +
        "</div></div>";
    }

    if (state.format && state.format !== "text") {
      h += '<div class="notice" style="background:var(--surface-2);' +
        'border-color:var(--line)"><span aria-hidden="true">\u25CB</span><div>' +
        "Parsed as <b>" + esc(state.format) + "</b> \u2014 " + esc(state.detail || "") +
        "</div></div>";
    }

    (state.warnings || []).forEach(function (w) {
      h += '<div class="notice" style="background:var(--surface-2);' +
        'border-color:var(--line)"><span aria-hidden="true">\u25CB</span><div>' +
        esc(w) + "</div></div>";
    });

    if (counts.already_masked) {
      h += '<div class="notice" style="background:var(--surface-2);' +
        'border-color:var(--line)"><span aria-hidden="true">\u25CB</span><div>' +
        counts.already_masked + " value" + (counts.already_masked === 1 ? " was" : "s were") +
        " already redacted in this file and are not counted below.</div></div>";
    }

    if (counts.clustered) {
      h += '<div class="notice"><span aria-hidden="true">\u25CF</span><div>' +
        "<b>" + counts.clustered + " excerpt" + (counts.clustered === 1 ? "" : "s") +
        " contain another person's SSN.</b> Those are covered too, so a card is " +
        "safe to paste into a ticket while the reveal switch is off.</div></div>";
    }

    h += '<div class="toolbar"><div class="segmented">';
    ["all", "high", "medium", "low"].forEach(function (f) {
      h += '<button data-filter="' + f + '" aria-pressed="' +
        (state.filter === f) + '">' + f + "</button>";
    });
    h += "</div>";

    h += '<div class="right">' +
      '<label class="switch"><input type="checkbox" id="reveal"' +
      (state.revealAll ? " checked" : "") + '><span class="track"></span>' +
      "<span>Reveal numbers</span></label>" +
      '<button class="btn btn-ghost btn-sm" id="csv">CSV</button>' +
      '<button class="btn btn-ghost btn-sm" id="json">JSON</button>' +
      '<button class="btn btn-ghost btn-sm" id="wipe">Wipe</button>' +
      "</div></div>";

    var shown = state.findings.filter(function (f) {
      return state.filter === "all" || f.confidence === state.filter;
    });

    shown.forEach(function (f, i) {
      var open = state.revealAll || !!state.revealed[f.id];
      var delay = Math.min(i * 0.03, 0.35);

      h += '<article class="find ' + f.confidence + '">' +
        '<div class="find-head">' +
        '<span class="badge ' + f.confidence + '">' + f.confidence + "</span>" +
        '<span class="locus">' + esc(f.location || ("line " + f.line)) +
        " \u00b7 col " + f.column + "</span>" +
        (f.kind === "itin" ? '<span class="badge">ITIN</span>' : "") +
        (f.neighbors
          ? '<span class="badge">+' + f.neighbors + " nearby</span>"
          : "") +
        (f.occurrences > 1
          ? '<span class="badge">\u00d7' + f.occurrences + "</span>"
          : "") +
        '<div class="right">' +
        '<button class="btn btn-ghost btn-sm copy" data-id="' + f.id +
        '">Copy</button></div>' +
        "</div>" +

        '<div class="find-body"><div class="excerpt">' +
        (f.more_before ? '<span class="ell">\u2026 </span>' : "") +
        side(f.before, f.id, open, delay) + " " +
        hit(f.value, f.last4, { id: f.id, open: open, focal: true, delay: delay }) +
        " " + side(f.after, f.id, open, delay) +
        (f.more_after ? '<span class="ell"> \u2026</span>' : "") +
        "</div>";

      h += '<div class="reasons"><span class="reason">score ' +
        (f.score > 0 ? "+" : "") + f.score + "</span>";
      f.reasons.forEach(function (r) { h += '<span class="reason">' + esc(r) + "</span>"; });
      h += "</div></div></article>";
    });

    if (!shown.length) {
      h += '<div class="empty"><strong>Nothing at this level</strong>' +
        "<span>Try another filter.</span></div>";
    }

    h += "</section>";
    out.innerHTML = h;
    wire();
  }

  /* ------------------------------------------------------------------ *
   * events
   * ------------------------------------------------------------------ */

  function each(sel, fn) {
    Array.prototype.forEach.call(document.querySelectorAll(sel), fn);
  }

  function wire() {
    each(".segmented button", function (b) {
      b.addEventListener("click", function () {
        state.filter = b.getAttribute("data-filter");
        render();
      });
    });

    // clicking any covered number toggles that whole card
    each(".hit", function (b) {
      b.addEventListener("click", function () {
        var id = b.getAttribute("data-id");
        state.revealed[id] = !state.revealed[id];
        render();
      });
    });

    $("reveal").addEventListener("change", function (e) {
      state.revealAll = e.target.checked;
      state.revealed = {};
      render();
    });

    each(".copy", function (b) {
      b.addEventListener("click", function () {
        var f = state.findings.filter(function (x) {
          return String(x.id) === b.getAttribute("data-id");
        })[0];
        if (!f) { return; }
        copy(plain(f, state.revealAll || !!state.revealed[f.id]), b);
      });
    });

    $("csv").addEventListener("click", function () { download("csv"); });
    $("json").addEventListener("click", function () { download("json"); });
    $("wipe").addEventListener("click", function () {
      wipe("Everything this page was holding has been dropped.");
    });
  }

  /* ------------------------------------------------------------------ *
   * text output
   * ------------------------------------------------------------------ */

  function flat(segments, reveal) {
    return segments.map(function (s) {
      if (s.kind === "text") { return s.text; }
      return reveal ? s.text : "***-**-" + s.last4;
    }).join("");
  }

  function plain(f, reveal) {
    return (f.location || ("line " + f.line)) + ", col " + f.column +
      " [" + f.confidence + "] " +
      (reveal ? f.value : f.masked) + "\n" +
      flat(f.before, reveal).trim() + "  >>" +
      (reveal ? f.value : f.masked) + "<<  " +
      flat(f.after, reveal).trim();
  }

  function copy(text, btn) {
    var done = function () {
      var old = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(function () { btn.textContent = old; }, 1400);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { legacy(text, done); });
    } else {
      legacy(text, done);
    }
  }

  function legacy(text, done) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
  }

  function download(kind) {
    var reveal = state.revealAll;   // exports follow the reveal switch

    var rows = state.findings.map(function (f) {
      return {
        id: f.id,
        confidence: f.confidence,
        value: reveal ? f.value : f.masked,
        location: f.location || ("line " + f.line),
        line: f.line,
        column: f.column,
        offset: f.offset,
        neighbors: f.neighbors,
        reasons: f.reasons.join("; "),
        before: flat(f.before, reveal).trim(),
        after: flat(f.after, reveal).trim()
      };
    });

    var blob, name;
    if (kind === "json") {
      blob = new Blob(
        [JSON.stringify({ source: state.name, redacted: !reveal, findings: rows }, null, 2)],
        { type: "application/json" });
      name = "ssn-sweep.json";
    } else {
      var cols = ["id", "confidence", "value", "location", "line", "column",
                  "offset", "neighbors", "reasons", "before", "after"];
      var lines = [cols.join(",")];
      rows.forEach(function (r) {
        lines.push(cols.map(function (c) {
          return '"' + String(r[c]).replace(/"/g, '""') + '"';
        }).join(","));
      });
      blob = new Blob([lines.join("\r\n")], { type: "text/csv" });
      name = "ssn-sweep.csv";
    }

    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }
})();