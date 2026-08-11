#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Accuracy harness for detector.py. Run with: python test_detector.py

Each case is a snippet plus the band it should land in. The script scores the
corpus and reports precision, recall and F1 against the question that matters:
would an analyst be shown this, meaning high or medium.

To extend: when a real file produces a miss, redact the digits, keep the shape
and surrounding words, and add it as a case. It then cannot silently regress.
Exits non-zero on any false negative, so it drops into a pre-commit hook.
"""

from __future__ import print_function

import sys

from detector import BANDS, WEIGHTS, scan_text

SURFACED = ("high", "medium")

# (label, text, expected band or None for "should not match at all")
CASES = [
    # ---- should surface --------------------------------------------------
    ("labelled dashed", 'Record 4491,"SSN: 621-70-1901\\nDOB: 01/08/1994"', "high"),
    ("labelled spaced", "Employee SSN 511 08 7249 filed 07/06/2023", "high"),
    ("labelled bare", "SSN: 610212373 keyed on 07/25/2022", "high"),
    ("soc sec spelled out", "Social Security Number 452-11-8830 on file", "high"),
    ("dashed unlabelled with dob", "Tran, Minh 452-11-8830 born 09/24/1987", "high"),
    ("dashed alone", "Attached form lists 452-11-8830 for review", "medium"),
    ("csv column header", "name,ssn,dob\nTran Minh,452118830,09/24/1987", "high"),
    ("itin", "Taxpayer ID 912-75-4410 submitted with the return", "high"),
    ("en dash separator", "SSN: 452\u201311\u20138830 verified", "high"),
    ("spaced dashes", "SSN: 452 - 11 - 8830 verified", "high"),
    ("vietnamese label", "So bao hiem xa hoi 452-11-8830 da nop", "high"),
    ("bare in dob context", "DOB 09/24/1987 452118830 enrollment record", "medium"),
    ("sentence-ending period", "The form lists SSN 452-11-8830.", "high"),
    ("period before quote", 'Note read "SSN: 452-11-8830."', "high"),

    # ---- should be buried or not matched at all --------------------------
    ("phone number", "Call the office at 916-555-0134 before Friday", None),
    ("ten digit run", "Reference 9165550134 shipped Tuesday", None),
    ("zip plus four", "Sacramento CA 95814-1234 mailing address", None),
    ("date iso", "Effective 2023-07-01 keyed 07/06/2023", None),
    ("ip address", "Source 192.168.10.4501 blocked at the edge", None),
    ("version string", "Build 12.34.5678 deployed overnight", None),
    ("ein shape", "EIN 94-1234567 on the W-9", None),
    ("invoice number", "Invoice no 481920347 shipped 10/15/2020", "low"),
    ("order reference", "Order number 481-92-0347 dispatched", "low"),
    ("account number", "Account number 481920347 closed", "low"),
    ("bare digits alone", "Batch 481920347 processed overnight", "low"),
    ("dollar amount", "Total due $123-45-6789 adjustment", "low"),
    ("all zeros", "Placeholder 000-00-0000 pending", "low"),
    ("repdigits", "Test row 111-11-1111 in the fixture", "low"),
    ("sequential", "QA fixture 123-45-6789 seeded", "low"),
    ("invalid area 666", "Row 666-12-3456 rejected by validation", "low"),
    ("csv negative header", "name,invoice_no,date\nTran Minh,452118830,09/24/1987", "low"),
]


def band_of(text):
    """Band the strongest finding lands in, or None if nothing matched."""
    found = scan_text(text, 40)
    if not found:
        return None
    return max(found, key=lambda f: f["score"])["confidence"]


def main():
    """Score the corpus, print the report, and exit non-zero on a false negative."""
    tp = fp = fn = tn = 0
    exact = 0
    misses = []

    for name, text, expected in CASES:
        actual = band_of(text)
        should_surface = expected in SURFACED
        does_surface = actual in SURFACED

        if actual == expected:
            exact += 1
        elif should_surface == does_surface:
            pass                       # right side of the line, wrong band
        else:
            misses.append((name, expected, actual, text))

        if should_surface and does_surface:
            tp += 1
        elif should_surface and not does_surface:
            fn += 1
        elif not should_surface and does_surface:
            fp += 1
        else:
            tn += 1

    precision = tp / float(tp + fp) if tp + fp else 0.0
    recall = tp / float(tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0

    print("=" * 66)
    print("detector.py accuracy over %d cases" % len(CASES))
    print("bands: high >= %d, medium >= %d" % (BANDS["high"], BANDS["medium"]))
    print("=" * 66)
    print("surfaced correctly      %3d" % tp)
    print("buried correctly        %3d" % tn)
    print("false positives         %3d   noise an analyst has to wade through" % fp)
    print("false negatives         %3d   real PII that would be missed" % fn)
    print("-" * 66)
    print("precision %.3f   recall %.3f   F1 %.3f" % (precision, recall, f1))
    print("exact band match        %3d / %d" % (exact, len(CASES)))

    if misses:
        print("-" * 66)
        print("wrong side of the line:")
        for name, expected, actual, text in misses:
            print("  %-24s expected %-7s got %-7s" % (name, expected, actual))
            print("      %s" % text.replace("\n", " / ")[:70])

    print("=" * 66)
    print("weights: " + ", ".join("%s=%s" % kv for kv in sorted(WEIGHTS.items())))

    return 1 if fn else 0


if __name__ == "__main__":
    sys.exit(main())
