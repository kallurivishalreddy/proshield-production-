"""Report export renderers: Markdown / CSV / PDF (gap 14).

Reference: docs/PHASE 4/PROSHIELD-BACKEND-CAPABILITY-PATCH-REPORT.md.

The exporters render the REAL persisted :class:`Report` payload —
the exact data ``report.get`` serves — into the three documented
download formats. They never invent findings: every line traces
back to a report section item or report field.

Format contracts
----------------

* **markdown** — a GitHub-flavoured Markdown document. Full Unicode.
* **csv** — one row per report item, RFC 4180 quoting, UTF-8 with
  BOM so Excel opens it correctly. Full Unicode.
* **pdf** — a minimal, dependency-free PDF 1.4 writer (single font
  Helvetica, Latin-1 transcoding). Characters outside Latin-1 are
  transliterated to ``?`` *visibly* — the full-fidelity Unicode
  rendering lives in the Markdown/CSV exports. This limitation is
  documented in the patch report; it is honest and observable, not
  hidden.
"""
from __future__ import annotations

import csv
import io
from typing import Any, Dict, List, Tuple

from .models import Report


MEDIA_TYPES = {
    "json": "application/json",
    "markdown": "text/markdown; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "pdf": "application/pdf",
}

FILE_EXTENSIONS = {
    "json": "json",
    "markdown": "md",
    "csv": "csv",
    "pdf": "pdf",
}


# ------------------------------------------------------------------ shared
def _report_rows(report: Report) -> List[Dict[str, str]]:
    """Flatten the report into ordered (section, item) rows."""
    rows: List[Dict[str, str]] = []
    for section in report.sections:
        for item in section.items:
            rows.append({
                "section": section.title,
                "kind": item.kind,
                "reference_id": item.reference_id,
                "title": item.title,
                "text": item.text,
            })
    return rows


def _report_header(report: Report) -> List[Tuple[str, str]]:
    return [
        ("report_id", report.report_id),
        ("incident_id", report.incident_id),
        ("mode", report.mode.value),
        ("version", str(report.version)),
        ("title", report.title),
        ("generated_by", report.generated_by),
        ("generated_at", report.generated_at.isoformat()),
        ("is_centralized", str(report.is_centralized)),
        (
            "centralized_correlation_ids",
            ", ".join(report.centralized_correlation_ids),
        ),
        (
            "evidence_references",
            ", ".join(report.evidence_references),
        ),
        (
            "rule_references",
            ", ".join(
                f"{rid} v{ver}" for rid, ver in report.rule_references
            ),
        ),
    ]


# ------------------------------------------------------------------ markdown
def export_markdown(report: Report) -> str:
    lines: List[str] = [
        f"# {report.title or 'PROSHIELD Report'}",
        "",
    ]
    for key, value in _report_header(report):
        lines.append(f"- **{key}**: {value or '—'}")
    lines.append("")
    for section in report.sections:
        lines.append(f"## {section.title}")
        lines.append("")
        if not section.items:
            lines.append("_no evidence in this section_")
            lines.append("")
            continue
        for item in section.items:
            heading = item.title or item.reference_id or item.kind
            lines.append(f"### [{item.kind}] {heading}")
            if item.reference_id:
                lines.append(f"- reference: `{item.reference_id}`")
            if item.text:
                lines.append("")
                lines.append(item.text)
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ------------------------------------------------------------------ csv
def export_csv(report: Report) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow([
        "field", "value", "section", "kind", "reference_id",
        "title", "text",
    ])
    for key, value in _report_header(report):
        writer.writerow([key, value, "", "", "", "", ""])
    for row in _report_rows(report):
        writer.writerow([
            "", "", row["section"], row["kind"], row["reference_id"],
            row["title"], row["text"],
        ])
    # UTF-8 BOM so Excel detects the encoding (full Unicode preserved).
    return "\ufeff" + buf.getvalue()


# ------------------------------------------------------------------ pdf
_PDF_PAGE_WIDTH = 612   # US Letter points
_PDF_PAGE_HEIGHT = 792
_PDF_MARGIN = 54
_PDF_LINE_HEIGHT = 14
_PDF_FONT_SIZE = 10


def _pdf_escape(text: str) -> str:
    """Escape PDF string literals and transliterate to Latin-1."""
    out: List[str] = []
    for ch in text:
        if ch in ("\\", "(", ")"):
            out.append("\\" + ch)
            continue
        try:
            ch.encode("latin-1")
            out.append(ch)
        except UnicodeEncodeError:
            # Visible, honest transliteration — the Unicode original
            # remains available in the Markdown/CSV exports.
            out.append("?")
    return "".join(out)


def _wrap(text: str, max_chars: int) -> List[str]:
    if not text:
        return [""]
    lines: List[str] = []
    for paragraph in text.splitlines() or [""]:
        while len(paragraph) > max_chars:
            cut = paragraph.rfind(" ", 0, max_chars)
            if cut <= 0:
                cut = max_chars
            lines.append(paragraph[:cut])
            paragraph = paragraph[cut:].lstrip()
        lines.append(paragraph)
    return lines


def export_pdf(report: Report) -> bytes:
    """Render the report as a minimal, dependency-free PDF (multi-page)."""
    max_chars = int(
        (_PDF_PAGE_WIDTH - 2 * _PDF_MARGIN) / (_PDF_FONT_SIZE * 0.5)
    )
    lines_per_page = int(
        (_PDF_PAGE_HEIGHT - 2 * _PDF_MARGIN) / _PDF_LINE_HEIGHT
    )

    lines: List[str] = [report.title or "PROSHIELD Report", ""]
    for key, value in _report_header(report):
        lines.append(f"{key}: {value or '-'}")
    lines.append("")
    for section in report.sections:
        lines.append(f"== {section.title} ==")
        if not section.items:
            lines.append("  (no evidence in this section)")
            continue
        for item in section.items:
            heading = item.title or item.reference_id or item.kind
            lines.append(f"- [{item.kind}] {heading}")
            if item.reference_id:
                lines.append(f"  ref: {item.reference_id}")
            for sub in _wrap(item.text, max_chars - 2):
                lines.append(f"  {sub}")

    # Paginate deterministically.
    pages: List[List[str]] = []
    for start in range(0, len(lines), lines_per_page):
        pages.append(lines[start:start + lines_per_page])
    if not pages:
        pages = [["(empty report)"]]

    # One content stream per page.
    streams: List[bytes] = []
    for page_lines in pages:
        ops: List[str] = [
            "BT",
            f"/F1 {_PDF_FONT_SIZE} Tf",
            f"{_PDF_LINE_HEIGHT} TL",
            f"1 0 0 1 {_PDF_MARGIN} "
            f"{_PDF_PAGE_HEIGHT - _PDF_MARGIN} Tm",
        ]
        for text in page_lines:
            ops.append(f"({_pdf_escape(text)}) Tj T*")
        ops.append("ET")
        streams.append("\n".join(ops).encode("latin-1", errors="replace"))

    # Object layout:
    #  1 catalog, 2 pages, 3 font, then per page: page obj + content obj.
    n_pages = len(pages)
    page_objs: List[bytes] = []
    for idx in range(n_pages):
        content_ref = 4 + n_pages + idx
        page_objs.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 "
                f"{_PDF_PAGE_WIDTH} {_PDF_PAGE_HEIGHT}] "
                f"/Contents {content_ref} 0 R "
                f"/Resources << /Font << /F1 3 0 R >> >> >>"
            ).encode("latin-1")
        )
    objects: List[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        (
            "<< /Type /Pages /Kids ["
            + " ".join(
                f"{4 + idx} 0 R" for idx in range(n_pages)
            )
            + f"] /Count {n_pages} >>"
        ).encode("latin-1"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>",
    ]
    objects.extend(page_objs)
    for stream in streams:
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1")
            + stream
            + b"\nendstream"
        )

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets: List[int] = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode("latin-1"))
        out.write(obj)
        out.write(b"\nendobj\n")
    xref_at = out.tell()
    out.write(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    out.write(b"0000000000 65535 f \n")
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode("latin-1"))
    out.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_at}\n%%EOF\n".encode("latin-1")
    )
    return out.getvalue()


EXPORTERS = {
    "markdown": lambda report: export_markdown(report).encode("utf-8"),
    "csv": lambda report: export_csv(report).encode("utf-8"),
    "pdf": export_pdf,
}


def export_report(report: Report, fmt: str) -> Tuple[bytes, str, str]:
    """Render ``report`` in ``fmt``; returns (content, media_type, ext)."""
    if fmt == "json":
        import json

        return (
            json.dumps(report.to_dict(), indent=2).encode("utf-8"),
            MEDIA_TYPES["json"],
            FILE_EXTENSIONS["json"],
        )
    exporter = EXPORTERS.get(fmt)
    if exporter is None:
        raise ValueError(f"unsupported export format: {fmt!r}")
    return exporter(report), MEDIA_TYPES[fmt], FILE_EXTENSIONS[fmt]


__all__ = [
    "EXPORTERS",
    "FILE_EXTENSIONS",
    "MEDIA_TYPES",
    "export_csv",
    "export_markdown",
    "export_pdf",
    "export_report",
]
