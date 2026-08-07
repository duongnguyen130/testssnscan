#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detection engine for SSN Sweep.

Pure logic: no HTTP, no printing, no file I/O. Import scan_text() from here
and it will hand back every candidate SSN with word context around it.

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
    9-digit account numbers, drop the bare-run branch or require a label.
    """
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

        problems = structural_problems(area, group, serial)
        level, points, reasons = score(sep1, has_keyword, problems, digits)

        # word-based context: walk N tokens back and forward, then slice the
        # original text between those offsets so spacing survives intact
        i = max(bisect.bisect_right(word_starts, start) - 1, 0)
        j = max(bisect.bisect_right(word_starts, end - 1) - 1, 0)
        before = words[max(0, i - context_words):i]
        after = words[j + 1:j + 1 + context_words]

        if before:
            before_text = text[before[0][0]:start]
        elif words:
            before_text = text[words[i][0]:start]
        else:
            before_text = ""

        if after:
            after_text = text[end:after[-1][1]]
        elif words:
            after_text = text[end:words[j][1]]
        else:
            after_text = ""

        last_nl = text.rfind("\n", 0, start)

        findings.append({
            "id": len(findings) + 1,
            "value": m.group(0),
            "digits": digits,
            "masked": "***-**-" + serial,
            "last4": serial,
            "offset": start,
            "line": text.count("\n", 0, start) + 1,
            "column": start - last_nl,
            "confidence": level,
            "score": points,
            "reasons": reasons,
            "labeled": has_keyword,
            "valid_structure": not problems,
            "before": _squash(before_text),
            "after": _squash(after_text),
            "words_before": len(before),
            "words_after": len(after),
        })

    return findings


def summarize(findings):
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["confidence"]] += 1
    counts["total"] = len(findings)
    return counts
