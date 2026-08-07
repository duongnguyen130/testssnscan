/* SSN Sweep - front end.
   Posts to /scan and renders findings. Every SSN in an excerpt is covered,
   not just the focal one, so a card is safe to screenshot as-is. */

(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

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

  function load(f) {
    if (!f) { return; }
    var r = new FileReader();
    r.onload = function () {
      $("text").value = r.result;
      state.name = f.name;
      $("loaded").textContent = f.name + " \u00b7 " +
        r.result.length.toLocaleString() + " chars";
    };
    r.onerror = function () { fail("That file could not be read. Try a plain text file."); };
    r.readAsText(f);
  }

  $("clear").addEventListener("click", function () {
    $("text").value = "";
    $("file").value = "";
    $("loaded").textContent = "";
    $("out").innerHTML = "";
    state.findings = [];
    state.counts = null;
    state.name = "pasted text";
  });

  /* ------------------------------------------------------------------ *
   * scan
   * ------------------------------------------------------------------ */

  $("scan").addEventListener("click", function () {
    var text = $("text").value;
    if (!text.trim()) { fail("Add a file or paste some text first."); return; }

    var n = parseInt($("words").value, 10);
    if (isNaN(n) || n < 1) { n = 30; $("words").value = 30; }

    var btn = $("scan");
    btn.disabled = true;
    btn.textContent = "Scanning\u2026";

    fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text, context_words: n })
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.error) { fail(d.error); return; }
        state.findings = d.findings;
        state.counts = d.counts;
        state.revealed = {};
        state.revealAll = false;
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
        '<span class="locus">line ' + f.line + " \u00b7 col " + f.column +
        " \u00b7 offset " + f.offset + "</span>" +
        (f.neighbors
          ? '<span class="badge">+' + f.neighbors + " nearby</span>"
          : "") +
        '<div class="right">' +
        '<button class="btn btn-ghost btn-sm copy" data-id="' + f.id +
        '">Copy</button></div>' +
        "</div>" +

        '<div class="find-body"><div class="excerpt">' +
        (f.words_before ? '<span class="ell">\u2026 </span>' : "") +
        side(f.before, f.id, open, delay) + " " +
        hit(f.value, f.last4, { id: f.id, open: open, focal: true, delay: delay }) +
        " " + side(f.after, f.id, open, delay) +
        (f.words_after ? '<span class="ell"> \u2026</span>' : "") +
        "</div>";

      h += '<div class="reasons">';
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
    return "line " + f.line + ", col " + f.column + " [" + f.confidence + "] " +
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
      var cols = ["id", "confidence", "value", "line", "column", "offset",
                  "neighbors", "reasons", "before", "after"];
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
