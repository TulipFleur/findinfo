"""Spreadsheet export for the asset graph (`assets --export-xlsx`).

Why this module exists
----------------------
The only machine-readable export was JSONL (`assets --export`). Humans who
review a mapping engagement in Excel had to convert it themselves, and the
conversion usually lost the column meanings: `attrs` is a JSON blob, `sources`
is a comma-joined provenance string, endpoints are a separate table. This
module writes one workbook with a sheet per asset kind, flattening the fields
an operator actually sorts and filters on, and recording the scope decision
in a notes sheet so a filtered export cannot be mistaken for everything the
library holds.

openpyxl is an OPTIONAL dependency: the caller gets a structured error
(never a traceback, never a silent CSV fallback that would look like an xlsx)
when it is missing.
"""
from __future__ import annotations

from pathlib import Path

SHEETS = (
    ("domain", "域名", ("canonical", "parent", "confidence", "passivity",
                       "status", "title", "ip", "webserver", "tech",
                       "sources", "first_seen", "last_seen")),
    ("ip", "IP", ("canonical", "parent", "confidence", "passivity",
                  "sources", "first_seen", "last_seen")),
    ("url", "URL", ("canonical", "parent", "confidence", "passivity",
                    "status", "title", "sources", "first_seen", "last_seen")),
    ("company", "公司", ("canonical", "parent", "confidence", "sources",
                         "first_seen", "last_seen")),
    ("icp", "备案", ("canonical", "parent", "confidence", "sources",
                     "first_seen", "last_seen")),
)
ENDPOINT_SHEET = ("endpoint", "端点",
                  ("asset", "method", "path", "params", "status", "title",
                   "source", "first_seen", "last_seen"))


def _cell(value):
    """A JSON-safe, Excel-safe cell value.

    Lists (tech, cert SANs) become 'a, b'; dicts become '' rather than
    '[object Object]'. Long text keeps its content: openpyxl truncates on
    display, not on write.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(x) for x in value if x is not None)
    if isinstance(value, dict):
        return ""
    return str(value)


def _flatten(row: dict, fields) -> list:
    attrs = row.get("attrs")
    if not isinstance(attrs, dict):
        attrs = {}
    out = []
    for f in fields:
        if f in row:
            out.append(_cell(row.get(f)))
        else:
            out.append(_cell(attrs.get(f)))
    return out


def write_workbook(path, store, scope=None, min_conf: float = 0.0,
                   kinds=None, include_endpoints: bool = True,
                   notes=None) -> dict:
    """Write one .xlsx with a sheet per asset kind.

    `scope` is a domain-suffix filter (the same `match` the CLI uses); when
    given, rows outside it are EXCLUDED and the notes sheet records that, so
    the file cannot be read as the full library. Returns a summary dict.
    """
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except ImportError as exc:                      # pragma: no cover
        raise RuntimeError(
            "xlsx export needs the 'openpyxl' package (pip install openpyxl); "
            "the JSONL export (assets --export) has no extra dependency"
        ) from exc

    want = set(kinds or ()) if kinds else None
    wb = Workbook()
    wb.remove(wb.active)
    counts: dict = {}

    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="2F3B52")

    def add_sheet(title, fields, rows):
        ws = wb.create_sheet(title)
        ws.append(list(fields))
        for c in range(1, len(fields) + 1):
            cell = ws.cell(row=1, column=c)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(vertical="center")
        for r in rows:
            ws.append(_flatten(r, fields))
        ws.freeze_panes = "A2"
        # column widths from a bounded sample: enough to read, never huge
        for i, f in enumerate(fields, start=1):
            width = max(len(str(f)), 8)
            for r in rows[:200]:
                width = max(width, min(60, len(str(_flatten(r, fields)[i - 1]))))
            ws.column_dimensions[get_column_letter(i)].width = width + 2
        ws.auto_filter.ref = ws.dimensions
        return ws

    for kind, title, fields in SHEETS:
        if want and kind not in want:
            continue
        rows = store.get_assets(kind=kind, min_conf=min_conf,
                                match=scope or None)
        if not rows:
            continue
        add_sheet(title, fields, rows)
        counts[kind] = len(rows)

    if include_endpoints and (not want or "endpoint" in want):
        eps = store.get_endpoints()
        if scope:
            from . import core
            eps = [e for e in eps
                   if core.in_scope(e.get("asset") or "", scope)]
        if eps:
            add_sheet(ENDPOINT_SHEET[1], ENDPOINT_SHEET[2], eps)
            counts["endpoint"] = len(eps)

    # notes sheet: what this file IS and what it deliberately left out
    ws = wb.create_sheet("说明")
    ws.append(["字段", "值"])
    ws.cell(row=1, column=1).font = header_font
    ws.cell(row=1, column=1).fill = header_fill
    ws.cell(row=1, column=2).font = header_font
    ws.cell(row=1, column=2).fill = header_fill
    rows_out = [
        ("导出范围(match)", ", ".join(scope or []) or "(全库，未过滤)"),
        ("最小置信度", min_conf),
        ("工作表", ", ".join("%s(%d)" % (k, v) for k, v in counts.items()) or "无"),
        ("说明", "范围过滤只影响本文件；资产库本身仍是共享的、未删改"),
    ]
    for line in (notes or []):
        rows_out.append(("提示", line))
    for k, v in rows_out:
        ws.append([_cell(k), _cell(v)])
    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 90

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    wb.save(str(p))
    return {"path": str(p), "sheets": counts,
            "rows_total": sum(counts.values()),
            "scope": list(scope or [])}
