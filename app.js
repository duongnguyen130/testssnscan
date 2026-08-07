/* SSN Sweep - front end. Talks to POST /scan and renders the findings. */

(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  var state = {
    findings: [],
    counts: null,
    filter: "all",
    revealed: {},
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

  /* ---- file intake ---- */

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
      $("loaded").textContent =
        f.name + " loaded, " + r.result.length.toLocaleString() + " characters";
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

  /* ---- scan ---- */

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
        state.counts = d.counts;
        state.revealed = {};
        state.revealAll = false;
        render();
      })
      .catch(function () {
        fail("The scanner did not answer. Is the server still running?");
      })
      .finally(function () {
        $("scan").disabled = false;
        $("scan").textContent = "Scan";
      });
  });

  /* ---- render ---- */

  function render() {
    var out = $("out");
    var counts = state.counts;

    if (!counts || !counts.total) {
      out.innerHTML = '<div class="empty"><strong>Clean</strong>' +
        "No 3-2-4 digit run turned up in " + esc(state.name) + ".</div>";
      return;
    }

    var h = '<div class="tally">' +
      "<div><b>" + counts.total + "</b><span>candidates</span></div>" +
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

    h += '<label class="inline">' +
      '<input type="checkbox" id="unmasked"> Put full numbers in the export file</label>';

    var shown = state.findings.filter(function (f) {
      return state.filter === "all" || f.confidence === state.filter;
    });

    shown.forEach(function (f, i) {
      var open = state.revealAll || state.revealed[f.id];
      var val = open
        ? esc(f.value)
        : '<span class="bar">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>' + esc(f.last4);

      h += '<div class="find ' + f.confidence + '">' +
        '<div class="gutter"><span class="lvl">' + f.confidence + "</span>" +
        "L" + f.line + "<br>col " + f.column + "<br>@" + f.offset + "</div>" +
        '<div class="body"><div class="excerpt">' +
        (f.words_before ? '<span class="ell">&hellip;</span> ' : "") +
        esc(f.before) + " " +
        '<button class="hit" data-id="' + f.id + '" style="--d:' +
        Math.min(i * 0.03, 0.4) + 's" ' +
        'title="' + (open ? "Hide this number" : "Show this number") + '">' + val + "</button> " +
        esc(f.after) +
        (f.words_after ? ' <span class="ell">&hellip;</span>' : "") +
        "</div>" +
        '<div class="why">' + esc(f.reasons.join(" \u00b7 ")) + "</div>" +
        "</div></div>";
    });

    if (!shown.length) {
      h += '<div class="empty"><strong>Nothing at this level</strong>' +
        "Pick another filter above.</div>";
    }

    out.innerHTML = h;
    wire();
  }

  function wire() {
    Array.prototype.forEach.call(document.querySelectorAll(".chip"), function (b) {
      b.addEventListener("click", function () {
        state.filter = b.getAttribute("data-filter");
        render();
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll(".hit"), function (b) {
      b.addEventListener("click", function () {
        var id = b.getAttribute("data-id");
        state.revealed[id] = !state.revealed[id];
        render();
      });
    });

    $("reveal").addEventListener("click", function () {
      state.revealAll = !state.revealAll;
      render();
    });

    $("csv").addEventListener("click", function () { download("csv"); });
    $("json").addEventListener("click", function () { download("json"); });
  }

  /* ---- export ---- */

  function download(kind) {
    var box = $("unmasked");
    var full = box && box.checked;

    var rows = state.findings.map(function (f) {
      return {
        id: f.id,
        confidence: f.confidence,
        value: full ? f.value : f.masked,
        line: f.line,
        column: f.column,
        offset: f.offset,
        reasons: f.reasons.join("; "),
        before: f.before,
        after: f.after
      };
    });

    var blob, name;
    if (kind === "json") {
      blob = new Blob(
        [JSON.stringify({ source: state.name, findings: rows }, null, 2)],
        { type: "application/json" });
      name = "ssn-sweep.json";
    } else {
      var cols = ["id", "confidence", "value", "line", "column",
                  "offset", "reasons", "before", "after"];
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
