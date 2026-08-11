#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Text extraction for SSN Sweep.

Turns an uploaded file into flat text plus a per-line locator, so a finding
on line 12 can be reported as "Sheet1 row 12" or "page 3" instead of a
meaningless line number.

Everything here is standard library. That is easy for xlsx (a zip of XML)
and csv, and a real constraint for pdf -- see _pdf() for what it cannot do.

Python 3.7+.
"""

import csv
import io
import re
import zipfile
import zlib
import xml.etree.ElementTree as ET

TEXT_EXTS = (".txt", ".log", ".md", ".json", ".xml", ".htm", ".html")
CSV_EXTS = (".csv", ".tsv")
XLSX_EXTS = (".xlsx", ".xlsm", ".xltx")

NS_MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
NS_REL = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
NS_PKG = "{http://schemas.openxmlformats.org/package/2006/relationships}"


class ExtractionError(Exception):
    pass


# A malicious file is small on disk and enormous once expanded. Every
# decompression path below is bounded, and every XML document is checked for
# entity declarations before a parser ever sees it.
MAX_EXPANDED = 200 * 1024 * 1024      # ceiling on total inflated bytes
MAX_ONE_PART = 60 * 1024 * 1024       # ceiling on any single member/stream
MAX_ZIP_RATIO = 200                   # inflated / stored, per member


def _safe_xml(raw, what):
    """Parse XML only after refusing anything that can self-expand.

    ElementTree resolves internal entities, so a small file declaring nested
    entities ("billion laughs") can exhaust memory. Neither DTDs nor entities
    have any legitimate use in an xlsx part, so reject outright.
    """
    head = raw[:4096].lstrip()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in raw[:65536]:
        raise ExtractionError(
            "%s declares an XML DTD or entity. Legitimate spreadsheets do not, "
            "so this file is refused." % what)
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ExtractionError("%s is malformed: %s" % (what, exc))


def _safe_read(zf, name):
    """Read one zip member with size and compression-ratio ceilings."""
    try:
        info = zf.getinfo(name)
    except KeyError:
        raise KeyError(name)

    if info.file_size > MAX_ONE_PART:
        raise ExtractionError(
            "%s expands to %.0f MB. Refusing to open a file that inflates "
            "this far." % (name, info.file_size / 1048576.0))
    if info.compress_size and info.file_size / float(info.compress_size) > MAX_ZIP_RATIO:
        raise ExtractionError(
            "%s expands %.0fx its stored size, which is characteristic of a "
            "decompression bomb rather than a spreadsheet."
            % (name, info.file_size / float(info.compress_size)))

    with zf.open(name) as fh:
        data = fh.read(MAX_ONE_PART + 1)
    if len(data) > MAX_ONE_PART:
        raise ExtractionError("%s is larger than its declared size." % name)
    return data


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _decode(data):
    """Best-effort text decode. Tax exports are rarely clean utf-8."""
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="replace")


def _result(text, fmt, locators, warnings=None, detail=""):
    return text, {
        "format": fmt,
        "locators": locators,      # one entry per line, 0-indexed
        "warnings": warnings or [],
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# plain text
# ---------------------------------------------------------------------------

def _plain(data):
    text = _decode(data)
    lines = text.count("\n") + 1
    return _result(text, "text", [{"label": "line %d" % (i + 1)}
                                  for i in range(lines)],
                   detail="%d lines" % lines)


# ---------------------------------------------------------------------------
# csv / tsv
# ---------------------------------------------------------------------------

def _csv(data, filename):
    text = _decode(data)
    sample = text[:8192]

    if filename.lower().endswith(".tsv"):
        delim = "\t"
    else:
        try:
            delim = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
        except csv.Error:
            delim = ","

    rows, locators, warnings = [], [], []
    reader = csv.reader(io.StringIO(text), delimiter=delim)

    try:
        for n, row in enumerate(reader, 1):
            # tab-join so the column-header logic in detector.py can still
            # find field boundaries, and so a quoted comma cannot fake one
            rows.append("\t".join(c.replace("\t", " ") for c in row))
            locators.append({"label": "row %d" % n, "row": n})
    except csv.Error as exc:
        warnings.append("Stopped at row %d: %s" % (len(rows) + 1, exc))

    if not rows:
        raise ExtractionError("No rows could be read from this file.")

    return _result("\n".join(rows), "csv", locators, warnings,
                   "%d rows, delimiter %r" % (len(rows), delim))


# ---------------------------------------------------------------------------
# xlsx
# ---------------------------------------------------------------------------

def _col_letter(index):
    letters = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        letters = chr(65 + rem) + letters
    return letters


def _shared_strings(zf):
    try:
        raw = _safe_read(zf, "xl/sharedStrings.xml")
    except KeyError:
        return []
    out = []
    for si in _safe_xml(raw, "sharedStrings.xml"):
        # rich text splits one value across several <t> runs
        out.append("".join(t.text or "" for t in si.iter(NS_MAIN + "t")))
    return out


def _sheet_order(zf):
    """Sheet names in workbook order, paired with their part paths."""
    try:
        wb = _safe_xml(_safe_read(zf, "xl/workbook.xml"), "workbook.xml")
        rels = _safe_xml(_safe_read(zf, "xl/_rels/workbook.xml.rels"),
                         "workbook.xml.rels")
    except KeyError:
        return [(n, n) for n in sorted(
            p for p in zf.namelist() if p.startswith("xl/worksheets/"))]

    target = {}
    for rel in rels:
        target[rel.get("Id")] = rel.get("Target")

    sheets = []
    for sheet in wb.iter(NS_MAIN + "sheet"):
        rid = sheet.get(NS_REL + "id")
        path = target.get(rid, "")
        if path.startswith("/"):
            path = path[1:]
        elif not path.startswith("xl/"):
            path = "xl/" + path
        if path in zf.namelist():
            sheets.append((sheet.get("name") or "sheet", path))
    return sheets


def _cell_text(cell, shared):
    kind = cell.get("t")
    if kind == "inlineStr":
        return "".join(t.text or "" for t in cell.iter(NS_MAIN + "t"))
    value = cell.find(NS_MAIN + "v")
    if value is None or value.text is None:
        return ""
    if kind == "s":
        try:
            return shared[int(value.text)]
        except (ValueError, IndexError):
            return ""
    return value.text


def _xlsx(data):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ExtractionError("That is not a readable .xlsx file. If it is an "
                              "older .xls, save it as .xlsx first.")

    total = sum(i.file_size for i in zf.infolist())
    if total > MAX_EXPANDED:
        raise ExtractionError(
            "This workbook expands to %.0f MB in total, over the %d MB limit."
            % (total / 1048576.0, MAX_EXPANDED // 1048576))

    shared = _shared_strings(zf)
    sheets = _sheet_order(zf)
    if not sheets:
        raise ExtractionError("No worksheets found in this workbook.")

    lines, locators, warnings = [], [], []
    numeric_cells = 0

    for name, path in sheets:
        try:
            root = _safe_xml(_safe_read(zf, path), "sheet %s" % name)
        except ExtractionError:
            raise
        except (KeyError, ET.ParseError):
            warnings.append("Sheet %s could not be parsed and was skipped." % name)
            continue

        for row in root.iter(NS_MAIN + "row"):
            rownum = row.get("r") or str(len(lines) + 1)
            cells = []
            for cell in row.iter(NS_MAIN + "c"):
                value = _cell_text(cell, shared)
                if value and cell.get("t") is None:
                    numeric_cells += 1
                cells.append(value.replace("\t", " ").replace("\n", " "))
            lines.append("\t".join(cells))
            locators.append({"label": "%s row %s" % (name, rownum),
                             "sheet": name, "row": rownum})

    if not lines:
        raise ExtractionError("The workbook has no rows with content.")

    if numeric_cells:
        warnings.append(
            "Some cells are stored as numbers, not text. Excel drops leading "
            "zeros there, so an SSN beginning with 0 may appear as 8 digits "
            "and will not match.")

    return _result("\n".join(lines), "xlsx", locators, warnings,
                   "%d sheet(s), %d rows" % (len(sheets), len(lines)))


# ---------------------------------------------------------------------------
# pdf
#
# No stdlib PDF library exists, so this is a deliberately small extractor:
# inflate the content streams with zlib and pull the text-showing operators
# back out. It handles the ordinary case of a text-based PDF with simple
# fonts. It cannot handle encrypted files, scanned pages (that needs OCR),
# or CID fonts whose glyph ids are not Unicode. Each of those is reported
# rather than silently returning nothing.
# ---------------------------------------------------------------------------

def _pdf_strings(content):
    """Walk a content stream, returning text with rough line breaks."""
    out = []
    array_parts = None
    pending = []
    i, n = 0, len(content)

    while i < n:
        ch = content[i:i + 1]

        if ch == b"(":                                  # literal string
            i += 1
            depth, buf = 1, bytearray()
            while i < n and depth:
                c = content[i:i + 1]
                if c == b"\\":
                    nxt = content[i + 1:i + 2]
                    if nxt in b"nrtbf":
                        buf += {b"n": b"\n", b"r": b"\r", b"t": b"\t",
                                b"b": b"\b", b"f": b"\f"}[nxt]
                        i += 2
                    elif nxt.isdigit():
                        octal = content[i + 1:i + 4]
                        try:
                            buf.append(int(octal, 8) & 0xFF)
                        except ValueError:
                            pass
                        i += 1 + len(octal)
                    else:
                        buf += nxt
                        i += 2
                    continue
                if c == b"(":
                    depth += 1
                elif c == b")":
                    depth -= 1
                    if not depth:
                        i += 1
                        break
                buf += c
                i += 1
            text = buf.decode("latin-1", errors="replace")
            (array_parts if array_parts is not None else pending).append(text)
            continue

        if ch == b"<" and content[i + 1:i + 2] != b"<":  # hex string
            end = content.find(b">", i)
            if end < 0:
                break
            hexdigits = re.sub(rb"[^0-9A-Fa-f]", b"", content[i + 1:end])
            if len(hexdigits) % 2:
                hexdigits += b"0"
            try:
                raw = bytes.fromhex(hexdigits.decode("ascii"))
            except ValueError:
                raw = b""
            text = _decode_hex_string(raw)
            (array_parts if array_parts is not None else pending).append(text)
            i = end + 1
            continue

        if ch == b"[":
            array_parts = []
            i += 1
            continue

        if ch == b"]":
            if array_parts is not None:
                pending.append("".join(array_parts))
                array_parts = None
            i += 1
            continue

        if array_parts is not None and (ch.isdigit() or ch in b"-."):
            m = re.match(rb"-?[\d.]+", content[i:])
            if m:
                # a large negative kern is how PDFs express a word space
                try:
                    if float(m.group(0)) < -150:
                        array_parts.append(" ")
                except ValueError:
                    pass
                i += m.end()
                continue

        m = re.match(rb"[A-Za-z'\"*]+", content[i:])
        if m:
            op = m.group(0)
            if op in (b"Tj", b"TJ", b"'", b'"'):
                out.append("".join(pending))
                pending = []
                if op in (b"'", b'"'):
                    out.append("\n")
            elif op in (b"Td", b"TD", b"T*", b"ET"):
                out.append("\n")
                pending = []
            i += m.end()
            continue

        i += 1

    return "".join(out)


def _decode_hex_string(raw):
    """Hex strings are bytes; simple fonts give latin-1, CID fonts UTF-16BE."""
    if len(raw) >= 2 and raw[0:1] == b"\xfe" and raw[1:2] == b"\xff":
        return raw[2:].decode("utf-16-be", errors="replace")
    if len(raw) % 2 == 0 and raw[0::2].count(b"\x00") > len(raw) // 4:
        return raw.decode("utf-16-be", errors="replace")
    return raw.decode("latin-1", errors="replace")


def _pdf(data):
    if re.search(rb"/Encrypt\b", data):
        raise ExtractionError(
            "This PDF is encrypted. Decrypt or print it to a new PDF first.")

    page_count = len(re.findall(rb"/Type\s*/Page\b", data))
    pages, warnings = [], []
    raw_streams = 0

    for m in re.finditer(rb"stream\r?\n", data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        blob = data[start:end].rstrip(b"\r\n")
        try:
            # bounded inflate; an unbounded one is a decompression bomb
            obj = zlib.decompressobj()
            inflated = obj.decompress(blob, MAX_ONE_PART)
            if obj.unconsumed_tail:
                warnings.append("A stream inflated past %d MB and was skipped."
                                % (MAX_ONE_PART // 1048576))
                continue
            blob = inflated
        except zlib.error:
            raw_streams += 1
            if b"Tj" not in blob and b"TJ" not in blob:
                continue                      # image, font or unknown filter
        text = _pdf_strings(blob)
        if text.strip():
            pages.append(text)

    if not pages:
        if page_count:
            raise ExtractionError(
                "No text layer found across %d page(s). This is most likely a "
                "scan, which needs OCR before it can be scanned for SSNs."
                % page_count)
        raise ExtractionError("No readable text found in this PDF.")

    if page_count and len(pages) != page_count:
        warnings.append(
            "Recovered %d text block(s) from %d page(s); page numbers below "
            "are approximate." % (len(pages), page_count))

    if raw_streams:
        warnings.append(
            "%d stream(s) used a compression filter this extractor does not "
            "implement and were skipped." % raw_streams)

    warnings.append(
        "PDF text extraction is best-effort. Confirm anything important "
        "against the original document.")

    lines, locators = [], []
    for n, page in enumerate(pages, 1):
        for line in page.split("\n"):
            lines.append(line)
            locators.append({"label": "page %d" % n, "page": n})

    return _result("\n".join(lines), "pdf", locators, warnings,
                   "%d page block(s)" % len(pages))


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

def extract(data, filename=""):
    """Return (text, meta) for a file's bytes. Raises ExtractionError."""
    name = (filename or "").lower()

    if data[:4] == b"%PDF" or name.endswith(".pdf"):
        return _pdf(data)
    if data[:2] == b"PK" and name.endswith(XLSX_EXTS):
        return _xlsx(data)
    if name.endswith(CSV_EXTS):
        return _csv(data, name)
    if data[:2] == b"PK":
        raise ExtractionError(
            "This looks like a zip-based Office file. Only .xlsx is supported; "
            "export .docx or .pptx content to text first.")
    if b"\x00" in data[:2048] and not name.endswith(TEXT_EXTS):
        raise ExtractionError(
            "This file looks binary. Supported formats are .txt, .csv, .tsv, "
            ".xlsx and .pdf.")
    return _plain(data)


def locate(meta, line_number):
    """Map a 1-indexed line number back to a human-readable position."""
    locators = meta.get("locators") or []
    if 1 <= line_number <= len(locators):
        return locators[line_number - 1].get("label", "line %d" % line_number)
    return "line %d" % line_number
