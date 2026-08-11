#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detection engine for SSN Sweep.

Pure logic: no HTTP, no printing, no file I/O.

Two things worth knowing before tuning this:

1. An SSN has no checksum. There is no arithmetic that separates a real one
   from nine plausible digits. Everything below is circumstantial evidence,
   so the output is a ranking, not a verdict.

2. Every weight lives in WEIGHTS and every threshold in BANDS. Change them,
   then run test_detector.py to see what the change did to precision and
   recall. Tuning by eye moves both in directions you will not notice.

Python 3.7+, standard library only.
"""

import re
from collections import Counter

DEFAULT_CONTEXT_CHARS = 30

# ---------------------------------------------------------------------------
# tuning surface
# ---------------------------------------------------------------------------

WEIGHTS = {
    # how the number is written
    "sep_dash":        4,   # 123-45-6789
    "sep_space":       3,   # 123 45 6789
    "sep_dot":         2,   # 123.45.6789  (also matches some IDs)
    "sep_none":        0,   # 123456789

    # what sits around it
    "label_adjacent":  5,   # "SSN:" immediately before the digits
    "label_near":      3,   # a label somewhere in the window
    "dob_near":        2,   # a birth date or DOB label alongside
    "negative_near":  -4,   # "invoice no", "account", "phone" and friends
    "currency":       -5,   # $ prefix, % suffix, decimal amount
    "csv_header_pos":  5,   # the column header for this field says SSN
    "csv_header_neg": -5,   # the column header says something else entirely

    # what the digits themselves are
    "valid":           1,
    "invalid":        -5,   # violates SSA allocation rules
    "placeholder":    -3,   # 111-11-1111, 123-45-6789, sequential runs
    "repeated":       -2,   # same value all over the document
}

BANDS = {"high": 6, "medium": 3}     # score >= high, >= medium, else low

REPEAT_LIMIT = 10          # occurrences before a value looks like a sentinel
LABEL_ADJACENT_GAP = 12    # chars allowed between a label and the digits
LABEL_WINDOW = 60          # chars either side for a looser label search
NEGATIVE_WINDOW = 40

# ---------------------------------------------------------------------------
# patterns
# ---------------------------------------------------------------------------

DASHES = "-\u2013\u2014"            # hyphen, en dash, em dash
_SEP = r"(?:[ \t]*[" + DASHES + r".][ \t]*|[ \t])"

# The dot guards are conditional: a dot only disqualifies the match when it
# joins another digit, i.e. part of a longer dotted run like an IP or a
# version string. A plain sentence-ending period must not hide an SSN.
SSN_PATTERN = re.compile(
    r"(?<![0-9" + DASHES + r"])(?<![0-9]\.)"
    r"([0-9]{3})(" + _SEP + r"?)([0-9]{2})(" + _SEP + r"?)([0-9]{4})"
    r"(?![0-9" + DASHES + r"])(?!\.[0-9])"
)

# already-redacted values: XXX-XX-1234, ***-**-1234, XXXXX1234
MASKED_PATTERN = re.compile(
    r"(?<![0-9A-Za-z])[X*x#\u2022]{3}[- .]?[X*x#\u2022]{2}[- .]?([0-9]{4})(?![0-9])"
)

POSITIVE_LABEL = re.compile(
    r"(ssn|ss\s*#|s\.s\.|social\s*security|socsec|soc\s*sec"
    r"|taxpayer\s*id|tax\s*id|\btin\b|\bitin\b|national\s*id"
    r"|so\s*bao\s*hiem\s*xa\s*hoi)",
    re.IGNORECASE,
)

NEGATIVE_LABEL = re.compile(
    r"(invoice|order\s*(no|num|number|#)|account\s*(no|num|number|#)|acct"
    r"|phone|fax|mobile|\btel\b|policy\s*(no|number)|claim\s*(no|number)"
    r"|tracking|confirmation|reference|\bref\b|badge|employee\s*(id|no|#)"
    r"|\bein\b|routing|check\s*(no|number)|serial|asset\s*tag|ticket"
    r"|incident|purchase\s*order|\bpo\s*#|zip|postal|license|plate)",
    re.IGNORECASE,
)

DOB_LABEL = re.compile(
    r"(\bdob\b|date\s*of\s*birth|birth\s*date|\bborn\b"
    r"|\b(0?[1-9]|1[0-2])/(0?[1-9]|[12][0-9]|3[01])/(19|20)[0-9]{2}\b)",
    re.IGNORECASE,
)

CURRENCY_BEFORE = re.compile(r"[$\u20ac\u00a3\u00a5]\s*$")
CURRENCY_AFTER = re.compile(r"^\s*(%|USD|EUR|dollars?)\b", re.IGNORECASE)

DELIMITERS = [",", "\t", "|", ";"]


# ---------------------------------------------------------------------------
# digit-level checks
# ---------------------------------------------------------------------------

def structural_problems(area, group, serial):
    """SSA allocation rules. Returns a list of human-readable reasons."""
    problems = []
    if area == "000":
        problems.append("area 000 is never issued")
    elif area == "666":
        problems.append("area 666 is never issued")
    elif area[0] == "9":
        problems.append("area 900-999 is not an SSN")
    if group == "00":
        problems.append("group 00 is never issued")
    if serial == "0000":
        problems.append("serial 0000 is never issued")
    return problems


# ITIN group ranges, the 4th and 5th digits of a 9xx-xx-xxxx tax ID
ITIN_GROUPS = [(50, 65), (70, 88), (90, 92), (94, 99)]


def is_itin(area, group):
    if area[0] != "9":
        return False
    g = int(group)
    return any(lo <= g <= hi for lo, hi in ITIN_GROUPS)


def looks_synthetic(digits):
    """Repdigits, straight runs, and the usual sample numbers."""
    if len(set(digits)) == 1:
        return "all identical digits"

    ascending = all(int(digits[i + 1]) == (int(digits[i]) + 1) % 10
                    for i in range(len(digits) - 1))
    descending = all(int(digits[i + 1]) == (int(digits[i]) - 1) % 10
                     for i in range(len(digits) - 1))
    if ascending or descending:
        return "sequential digit run"

    known = {"078051120": "the Woolworth wallet number",
             "219099999": "an SSA advertising sample",
             "457555462": "a well-known sample number"}
    if digits in known:
        return known[digits]
    return None


# ---------------------------------------------------------------------------
# context-level checks
# ---------------------------------------------------------------------------

def _sep_kind(raw):
    """Normalise a separator to its type so ' - ' and '-' compare equal."""
    stripped = raw.strip(" \t")
    if stripped == "":
        return "space" if raw else "none"
    if stripped in DASHES:
        return "dash"
    if stripped == ".":
        return "dot"
    return "other"


def _proximity(pattern, text, start, end, window):
    """How close a label sits: directly in front, loosely nearby, or absent."""
    lead = text[max(0, start - (LABEL_ADJACENT_GAP + 24)):start]
    for m in pattern.finditer(lead):
        if len(lead) - m.end() <= LABEL_ADJACENT_GAP:
            return "adjacent", m.group(0)
    wide = text[max(0, start - window):end + window]
    m = pattern.search(wide)
    if m:
        return "near", m.group(0)
    return None, None


def _csv_column(text, start, end):
    """If this looks like a delimited export, name the column the hit sits in.

    Returns (header_text, field_index) or (None, None). Naive splitting, so
    it bails out whenever the row and header disagree on field count.
    """
    first_end = text.find("\n")
    if first_end < 0:
        return None, None
    header = text[:first_end].strip()
    if not header:
        return None, None

    delim = max(DELIMITERS, key=header.count)
    if header.count(delim) < 1:
        return None, None

    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    line = text[line_start:line_end]
    if line_start == 0:
        return None, None                       # the hit is in the header row

    fields = header.split(delim)
    if line.count(delim) != header.count(delim):
        return None, None                       # quoted delimiters, give up

    index, cursor = 0, line_start
    for chunk in line.split(delim):
        if cursor <= start < cursor + len(chunk) + len(delim):
            break
        cursor += len(chunk) + len(delim)
        index += 1

    if index >= len(fields):
        return None, None
    return fields[index].strip().strip('"'), index


def _currency_adjacent(text, start, end):
    return bool(CURRENCY_BEFORE.search(text[max(0, start - 4):start])
                or CURRENCY_AFTER.search(text[end:end + 8]))


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------

def score_match(text, mt, occurrences):
    """Weigh every signal for one candidate. Returns (band, points, reasons, kind)."""
    points, reasons = 0, []
    start, end = mt["start"], mt["end"]
    sep = mt["sep_kind"]

    key = {"dash": "sep_dash", "space": "sep_space",
           "dot": "sep_dot", "none": "sep_none"}[sep]
    points += WEIGHTS[key]
    reasons.append({"dash": "3-2-4 dashed form", "space": "3-2-4 spaced form",
                    "dot": "3-2-4 dotted form",
                    "none": "bare 9-digit run"}[sep])

    # --- what the digits are -------------------------------------------------
    itin = is_itin(mt["area"], mt["group"])
    problems = structural_problems(mt["area"], mt["group"], mt["serial"])
    kind = "ssn"

    if itin:
        kind = "itin"
        points += WEIGHTS["valid"]
        reasons.append("matches the ITIN range, still taxpayer PII")
        problems = [p for p in problems if not p.startswith("area 900")]
        for p in problems:
            points += WEIGHTS["invalid"]
            reasons.append(p)
    elif problems:
        points += WEIGHTS["invalid"]
        reasons.extend(problems)
    else:
        points += WEIGHTS["valid"]

    synthetic = looks_synthetic(mt["digits"])
    if synthetic:
        points += WEIGHTS["placeholder"]
        reasons.append(synthetic)

    if occurrences >= REPEAT_LIMIT:
        points += WEIGHTS["repeated"]
        reasons.append("repeats %d times in this file" % occurrences)

    # --- what surrounds it ---------------------------------------------------
    # Adjacency outranks proximity in both directions. An "Invoice no" sitting
    # directly in front beats an "SSN" three lines away, which is exactly the
    # situation dense reports and PDF text layers produce.
    pos, _ = _proximity(POSITIVE_LABEL, text, start, end, LABEL_WINDOW)
    neg, neg_text = _proximity(NEGATIVE_LABEL, text, start, end, NEGATIVE_WINDOW)

    label = None
    if pos == "adjacent":
        points += WEIGHTS["label_adjacent"]
        reasons.append("SSN label directly in front")
        label = pos
    elif neg == "adjacent":
        points += WEIGHTS["negative_near"]
        reasons.append('reads as "%s", not an SSN' % neg_text.lower())
    elif pos == "near":
        points += WEIGHTS["label_near"]
        reasons.append("SSN label nearby")
        label = pos
    elif neg == "near":
        points += WEIGHTS["negative_near"]
        reasons.append('reads as "%s", not an SSN' % neg_text.lower())

    header, _ = _csv_column(text, start, end)
    if header:
        if POSITIVE_LABEL.search(header):
            points += WEIGHTS["csv_header_pos"]
            reasons.append('column "%s"' % header[:32])
        elif NEGATIVE_LABEL.search(header):
            points += WEIGHTS["csv_header_neg"]
            reasons.append('column "%s"' % header[:32])

    if DOB_LABEL.search(text[max(0, start - LABEL_WINDOW):end + LABEL_WINDOW]):
        points += WEIGHTS["dob_near"]
        reasons.append("birth date alongside")

    if _currency_adjacent(text, start, end):
        points += WEIGHTS["currency"]
        reasons.append("reads as a monetary amount")

    if points >= BANDS["high"]:
        band = "high"
    elif points >= BANDS["medium"]:
        band = "medium"
    else:
        band = "low"
    return band, points, reasons, kind


# ---------------------------------------------------------------------------
# context segments
# ---------------------------------------------------------------------------

def _collapse(s):
    return re.sub(r"\s+", " ", s)


def _segments(text, lo, hi, matches):
    """Slice text[lo:hi] into plain-text and ssn segments.

    Every match in the window becomes its own segment so the caller can
    redact all of them, not only the focal one.
    """
    segs, cursor = [], lo
    for m in matches:
        if m["end"] <= lo or m["start"] >= hi:
            continue
        s, e = max(m["start"], lo), min(m["end"], hi)
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


def _snap(lo, hi, matches):
    """Widen a window so a character cut never slices a match in half."""
    for m in matches:
        if m["end"] <= lo or m["start"] >= hi:
            continue
        lo, hi = min(lo, m["start"]), max(hi, m["end"])
    return lo, hi


def flatten(segments, mask=True):
    out = []
    for s in segments:
        if s["kind"] == "ssn":
            out.append("***-**-" + s["last4"] if mask else s["text"])
        else:
            out.append(s["text"])
    return "".join(out).strip()


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def _raw_matches(text):
    found = []
    for m in SSN_PATTERN.finditer(text):
        area, sep1, group, sep2, serial = m.groups()
        k1, k2 = _sep_kind(sep1), _sep_kind(sep2)
        if k1 != k2:
            continue                    # "123-45 6789" is a coincidence
        found.append({
            "start": m.start(), "end": m.end(), "value": m.group(0),
            "area": area, "group": group, "serial": serial,
            "sep_kind": k1, "digits": area + group + serial,
        })
    return found


def scan_text(text, context_chars=DEFAULT_CONTEXT_CHARS):
    """Find every candidate and return it with surrounding character context."""
    matches = _raw_matches(text)
    if not matches:
        return []

    tally = Counter(m["digits"] for m in matches)
    findings = []

    for n, mt in enumerate(matches, 1):
        start, end = mt["start"], mt["end"]
        occurrences = tally[mt["digits"]]
        band, points, reasons, kind = score_match(text, mt, occurrences)

        lo, _ = _snap(max(0, start - context_chars), start, matches)
        _, hi = _snap(end, min(len(text), end + context_chars), matches)

        before = _segments(text, lo, start, matches)
        after = _segments(text, end, hi, matches)
        last_nl = text.rfind("\n", 0, start)

        findings.append({
            "id": n,
            "kind": kind,
            "value": mt["value"],
            "digits": mt["digits"],
            "masked": "***-**-" + mt["serial"],
            "last4": mt["serial"],
            "offset": start,
            "line": text.count("\n", 0, start) + 1,
            "column": start - last_nl,
            "confidence": band,
            "score": points,
            "reasons": reasons,
            "occurrences": occurrences,
            "before": before,
            "after": after,
            "chars_before": start - lo,
            "chars_after": hi - end,
            "more_before": lo > 0,
            "more_after": hi < len(text),
            "neighbors": sum(1 for s in before + after if s["kind"] == "ssn"),
        })

    return findings


def count_already_masked(text):
    """Values someone already redacted. Not findings, but worth reporting."""
    return len(MASKED_PATTERN.findall(text))


def excerpt(finding, reveal=False):
    value = finding["value"] if reveal else finding["masked"]
    return "%s  >>%s<<  %s" % (flatten(finding["before"], not reveal), value,
                               flatten(finding["after"], not reveal))


def summarize(findings, text=None):
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["confidence"]] += 1
    counts["total"] = len(findings)
    counts["clustered"] = sum(1 for f in findings if f["neighbors"])
    counts["itin"] = sum(1 for f in findings if f["kind"] == "itin")
    counts["already_masked"] = count_already_masked(text) if text else 0
    return counts
