#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detection engine for SSN Sweep.

Pure logic: no HTTP, no printing, no file I/O.

The important bit: context is returned as *segments*, not as a flat string.
Record exports put several SSNs a few words apart, so one finding's context
window routinely contains other people's numbers. Every match inside a window
is tagged, which lets the caller redact all of them.

Python 3.7+, standard library only.
"""

import bisect
import re

DEFAULT_CONTEXT_WORDS = 30
KEYWORD_WINDOW = 60          # chars either side to look for a label

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


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------

def structural_problems(area, group, serial):
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


def score(sep, has_keyword, problems, digits):
    """Turn the signals into high / medium / low plus the reasons why.

    Tune these weights against your own data. If the corpus is full of
    9-digit account numbers, raise the bar on the bare-run branch or
    require a label outright.
    """
    points = 0
    reasons = []

    if sep == "-":
        points += 4
        reasons.append("3-2-4 dashed form")
    elif sep == " ":
        points += 3
        reasons.append("3-2-4 spaced form")
    else:
        reasons.append("bare 9-digit run")

    if has_keyword:
        points += 3
        reasons.append("SSN label nearby")

    if problems:
        points -= 4
        reasons.extend(problems)
    else:
        points += 1

    if digits in PLACEHOLDERS:
        points -= 2
        reasons.append("known test value")

    if points >= 5:
        level = "high"
    elif points >= 3:
        level = "medium"
    else:
        level = "low"
    return level, points, reasons


# ---------------------------------------------------------------------------
# context
# ---------------------------------------------------------------------------

def _collapse(s):
    """Collapse whitespace runs, keeping edge spaces so segments still join."""
    return re.sub(r"\s+", " ", s)


def _segments(text, lo, hi, matches):
    """Slice text[lo:hi] into plain-text and ssn segments.

    Every match falling in the window becomes its own segment, so the caller
    can redact all of them rather than only the focal one.
    """
    segs = []
    cursor = lo

    for m in matches:
        if m["end"] <= lo or m["start"] >= hi:
            continue
        s = max(m["start"], lo)
        e = min(m["end"], hi)
        if s > cursor:
            segs.append({"kind": "text", "text": _collapse(text[cursor:s])})
        segs.append({"kind": "ssn", "text": text[s:e], "last4": m["serial"]})
        cursor = e

    if cursor < hi:
        segs.append({"kind": "text", "text": _collapse(text[cursor:hi])})

    if segs and segs[0]["kind"] == "text":
        segs[0]["text"] = segs[0]["text"].lstrip()
    if segs and segs[-1]["kind"] == "text":
        segs[-1]["text"] = segs[-1]["text"].rstrip()

    return [s for s in segs if s["kind"] != "text" or s["text"]]


def flatten(segments, mask=True):
    """Flatten segments back to a string, redacting every SSN if asked."""
    out = []
    for s in segments:
        if s["kind"] == "ssn":
            out.append("***-**-" + s["last4"] if mask else s["text"])
        else:
            out.append(s["text"])
    return "".join(out).strip()


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------

def _raw_matches(text):
    """All accepted candidate spans, in document order."""
    found = []
    for m in SSN_PATTERN.finditer(text):
        area, sep1, group, sep2, serial = m.groups()
        if sep1 != sep2:
            # "123-45 6789" is a coincidence, not a formatted SSN
            continue
        found.append({
            "start": m.start(),
            "end": m.end(),
            "value": m.group(0),
            "area": area,
            "group": group,
            "serial": serial,
            "sep": sep1,
            "digits": area + group + serial,
        })
    return found


def scan_text(text, context_words=DEFAULT_CONTEXT_WORDS):
    """Find every candidate SSN and return it with surrounding word context."""
    matches = _raw_matches(text)
    if not matches:
        return []

    words = [(m.start(), m.end()) for m in WORD_PATTERN.finditer(text)]
    word_starts = [w[0] for w in words]
    findings = []

    for n, mt in enumerate(matches, 1):
        start, end = mt["start"], mt["end"]

        window = text[max(0, start - KEYWORD_WINDOW):end + KEYWORD_WINDOW]
        has_keyword = bool(KEYWORD_PATTERN.search(window))

        problems = structural_problems(mt["area"], mt["group"], mt["serial"])
        level, points, reasons = score(mt["sep"], has_keyword, problems,
                                       mt["digits"])

        # walk N words back and forward, then slice the original text between
        # those offsets so the excerpt keeps its real spacing
        i = max(bisect.bisect_right(word_starts, start) - 1, 0)
        j = max(bisect.bisect_right(word_starts, end - 1) - 1, 0)
        before_words = words[max(0, i - context_words):i]
        after_words = words[j + 1:j + 1 + context_words]

        lo = before_words[0][0] if before_words else start
        hi = after_words[-1][1] if after_words else end

        before = _segments(text, lo, start, matches)
        after = _segments(text, end, hi, matches)

        last_nl = text.rfind("\n", 0, start)

        findings.append({
            "id": n,
            "value": mt["value"],
            "digits": mt["digits"],
            "masked": "***-**-" + mt["serial"],
            "last4": mt["serial"],
            "offset": start,
            "line": text.count("\n", 0, start) + 1,
            "column": start - last_nl,
            "confidence": level,
            "score": points,
            "reasons": reasons,
            "labeled": has_keyword,
            "valid_structure": not problems,
            "before": before,
            "after": after,
            "words_before": len(before_words),
            "words_after": len(after_words),
            "neighbors": sum(1 for s in before + after if s["kind"] == "ssn"),
        })

    return findings


def excerpt(finding, reveal=False):
    """One-line rendering of a finding's context, for the console."""
    value = finding["value"] if reveal else finding["masked"]
    return "%s  >>%s<<  %s" % (
        flatten(finding["before"], not reveal),
        value,
        flatten(finding["after"], not reveal),
    )


def summarize(findings):
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["confidence"]] += 1
    counts["total"] = len(findings)
    counts["clustered"] = sum(1 for f in findings if f["neighbors"])
    return counts
