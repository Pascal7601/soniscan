"""Render a report snapshot as a PDF.

Pure: takes the snapshot dict stored on a Report (see services.generate_report) and returns bytes.
No Django, no database, no network (enforced by .importlinter), so it can be tested in isolation
and the same snapshot always produces the same file (reportlab `invariant` mode fixes the
timestamps and the document id).

Everything that came from outside the snapshot's own structure (asset names, risk-acceptance
reasons, library text) goes through `_p()`, which escapes the markup characters reportlab's
Paragraph would otherwise interpret.
"""

from __future__ import annotations

import io
import re
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SUPPORTED_SNAPSHOT_VERSIONS = (1,)

INK = colors.HexColor("#1f2933")
MUTED = colors.HexColor("#616e7c")
RULE = colors.HexColor("#d9dee4")
PANEL = colors.HexColor("#f4f6f8")

SEVERITY_COLOUR = {
    "critical": colors.HexColor("#b42318"),
    "high": colors.HexColor("#d9480f"),
    "medium": colors.HexColor("#b7791f"),
    "low": colors.HexColor("#2b6cb0"),
    "info": colors.HexColor("#616e7c"),
}
GRADE_COLOUR = {
    "A": colors.HexColor("#1f7a4d"),
    "B": colors.HexColor("#4d8f2a"),
    "C": colors.HexColor("#b7791f"),
    "D": colors.HexColor("#d9480f"),
    "F": colors.HexColor("#b42318"),
}
TIER_LABEL = {
    "fix_now": "Fix now",
    "fix_this_month": "Fix this month",
    "plan_later": "Plan for later",
}
EFFORT_LABEL = {
    "minutes": "Minutes",
    "hours": "A few hours",
    "days": "Days",
}
FIX_FIRST_COUNT = 5

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class ReportRenderError(ValueError):
    pass


# ---- text helpers ----------------


def _clean(value: object) -> str:
    """Printable text the built-in PDF fonts can draw (Windows-1252); anything else becomes '?'."""
    text = _CONTROL.sub("", str(value))
    return text.encode("cp1252", "replace").decode("cp1252")


def _p(value: object) -> str:
    return escape(_clean(value))


def _date(value: str | None) -> str:
    if not value:
        return ""
    return datetime.fromisoformat(value).strftime("%d %b %Y").lstrip("0")


def _hex(colour: colors.Color) -> str:
    return "#" + colour.hexval()[2:]


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


# ---- styles ----------------


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()["Normal"]

    def style(name: str, **kw: Any) -> ParagraphStyle:
        kw.setdefault("fontName", "Helvetica")
        kw.setdefault("textColor", INK)
        return ParagraphStyle(name, parent=base, **kw)

    return {
        "title": style("title", fontName="Helvetica-Bold", fontSize=22, leading=26),
        "subtitle": style("subtitle", fontSize=11, leading=15, textColor=MUTED),
        "h1": style(
            "h1", fontName="Helvetica-Bold", fontSize=14, leading=18, spaceBefore=14, spaceAfter=6
        ),
        "h2": style("h2", fontName="Helvetica-Bold", fontSize=11, leading=14),
        "body": style("body", fontSize=9.5, leading=13.5, alignment=TA_LEFT),
        "small": style("small", fontSize=8.5, leading=11.5, textColor=MUTED),
        "label": style("label", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=MUTED),
        "step": style("step", fontSize=9.5, leading=13.5, leftIndent=14, firstLineIndent=-14),
        "cell": style("cell", fontSize=8.5, leading=11),
        "cellhead": style(
            "cellhead", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=MUTED
        ),
        "grade": style(
            "grade", fontName="Helvetica-Bold", fontSize=40, leading=44, textColor=colors.white,
            alignment=1,
        ),  # fmt: skip
        "score": style("score", fontName="Helvetica-Bold", fontSize=26, leading=30),
    }


# ---- page furniture ----------------


def _numbered_canvas(footer_left: str) -> type[rl_canvas.Canvas]:
    class NumberedCanvas(rl_canvas.Canvas):
        """Two-pass canvas so the footer can say 'Page 2 of 5'."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._saved_pages: list[dict[str, Any]] = []

        def showPage(self) -> None:  # noqa: N802 (reportlab API)
            self._saved_pages.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            total = len(self._saved_pages)
            for state in self._saved_pages:
                self.__dict__.update(state)
                self._draw_footer(total)
                super().showPage()
            super().save()

        def _draw_footer(self, total: int) -> None:
            self.saveState()
            self.setStrokeColor(RULE)
            self.setLineWidth(0.5)
            self.line(18 * mm, 15 * mm, A4[0] - 18 * mm, 15 * mm)
            self.setFont("Helvetica", 8)
            self.setFillColor(MUTED)
            self.drawString(18 * mm, 10.5 * mm, footer_left)
            self.drawRightString(A4[0] - 18 * mm, 10.5 * mm, f"Page {self._pageNumber} of {total}")
            self.restoreState()

    return NumberedCanvas


# ---- building blocks ----------------


def _headline(snapshot: dict[str, Any]) -> str:
    posture = snapshot["posture"]
    tiers = posture["counts_by_tier"]
    open_count = len(snapshot["findings"])
    if open_count == 0:
        return "No open issues were found in this scan. Nothing needs fixing right now."
    parts = []
    if tiers.get("fix_now"):
        parts.append(f"{tiers['fix_now']} to fix now")
    if tiers.get("fix_this_month"):
        parts.append(f"{tiers['fix_this_month']} to fix this month")
    if tiers.get("plan_later"):
        parts.append(f"{tiers['plan_later']} to plan for later")
    return f"{_plural(open_count, 'issue')} open: " + ", ".join(parts) + "."


def _score_panel(snapshot: dict[str, Any], s: dict[str, ParagraphStyle]) -> Table:
    posture = snapshot["posture"]
    grade = posture["grade"]
    grade_cell = Paragraph(_p(grade), s["grade"])
    lines = [
        Paragraph(
            f"{posture['score']} <font size=12 color='{_hex(MUTED)}'>out of 100</font>", s["score"]
        ),
        Paragraph(_p(_headline(snapshot)), s["body"]),
    ]
    previous = snapshot.get("previous")
    if previous:
        delta = posture["score"] - previous["score"]
        if delta > 0:
            movement = f"Up {delta} points"
        elif delta < 0:
            movement = f"Down {-delta} points"
        else:
            movement = "No change"
        lines.append(
            Paragraph(
                _p(
                    f"{movement} since the report of {_date(previous['generated_at'])} "
                    f"(then {previous['score']}, grade {previous['grade']})."
                ),
                s["small"],
            )
        )
    if posture.get("capped_by"):
        lines.append(
            Paragraph(
                _p(
                    f"The score is held down because of an open {posture['capped_by']} issue, "
                    "however much else is in good shape. Fixing it lifts the limit."
                ),
                s["small"],
            )
        )
    table = Table([[grade_cell, lines]], colWidths=[28 * mm, None])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), GRADE_COLOUR.get(grade, MUTED)),
                ("BACKGROUND", (1, 0), (1, 0), PANEL),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (1, 0), (1, 0), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    return table


def _finding_block(
    number: int | None, f: dict[str, Any], s: dict[str, ParagraphStyle]
) -> KeepTogether:
    sev = f["severity"]
    colour = _hex(SEVERITY_COLOUR.get(sev, MUTED))
    prefix = f"{number}. " if number is not None else ""
    meta = (
        f"<font color='{colour}'><b>{_p(sev.upper())}</b></font>"
        f" &nbsp;|&nbsp; {_p(TIER_LABEL.get(f['tier'], f['tier']))}"
        f" &nbsp;|&nbsp; Where: {_p(f['asset'])}"
        f" &nbsp;|&nbsp; Effort: {_p(EFFORT_LABEL.get(f['effort'], f['effort']))}"
    )
    flow: list[Any] = [
        Paragraph(f"{prefix}{_p(f['title'])}", s["h2"]),
        Spacer(1, 2),
        Paragraph(meta, s["small"]),
        Spacer(1, 4),
        Paragraph(_p(f["plain_explanation"]), s["body"]),
        Spacer(1, 3),
        Paragraph(f"<b>Why it matters.</b> {_p(f['why_it_matters'])}", s["body"]),
    ]
    if f.get("owner_hint"):
        owner = f"<b>Who can fix it.</b> {_p(f['owner_hint'])}"
        flow += [Spacer(1, 3), Paragraph(owner, s["body"])]
    steps = f.get("fix_steps") or []
    if steps:
        flow += [Spacer(1, 3), Paragraph("<b>How to fix it</b>", s["body"])]
        flow += [Paragraph(f"{i}. {_p(step)}", s["step"]) for i, step in enumerate(steps, start=1)]
    flow += [Spacer(1, 8), HRFlowable(width="100%", thickness=0.5, color=RULE), Spacer(1, 8)]
    return KeepTogether(flow)


def _table(
    header: list[str], rows: list[list[str]], widths: list[float], s: dict[str, ParagraphStyle]
) -> Table:
    data = [[Paragraph(_p(h), s["cellhead"]) for h in header]]
    data += [[Paragraph(_p(c), s["cell"]) for c in row] for row in rows]
    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PANEL),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, RULE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


# ---- the document ----------------


def render_pdf(snapshot: dict[str, Any]) -> bytes:
    version = snapshot.get("version")
    if version not in SUPPORTED_SNAPSHOT_VERSIONS:
        raise ReportRenderError(f"unsupported report snapshot version: {version!r}")

    s = _styles()
    findings: list[dict[str, Any]] = snapshot["findings"]
    scan = snapshot["scan"]
    domain = snapshot["domain"]
    story: list[Any] = [
        Paragraph("Security posture report", s["title"]),
        Spacer(1, 3),
        Paragraph(
            _p(f"{domain}  |  prepared for {snapshot['organisation']}  |  "
               f"{_date(snapshot['generated_at'])}"),
            s["subtitle"],
        ),  # fmt: skip
        Spacer(1, 14),
        _score_panel(snapshot, s),
    ]

    top, rest = findings[:FIX_FIRST_COUNT], findings[FIX_FIRST_COUNT:]
    if top:
        story.append(Paragraph("Fix these first", s["h1"]))
        story.append(
            Paragraph(
                "Ranked by how much risk each one removes, with the quickest fix first when two "
                "are equally serious.",
                s["small"],
            )
        )
        story.append(Spacer(1, 8))
        story += [_finding_block(i, f, s) for i, f in enumerate(top, start=1)]
    if rest:
        story.append(Paragraph("Other open issues", s["h1"]))
        story += [_finding_block(None, f, s) for f in rest]

    accepted = snapshot.get("accepted", [])
    if accepted:
        story.append(Paragraph("Risks your organisation has accepted", s["h1"]))
        story.append(
            Paragraph(
                "These are not counted in the score. Each is reviewed on the date shown; if the "
                "issue is still present then, it counts again.",
                s["small"],
            )
        )
        story.append(Spacer(1, 6))
        story.append(
            _table(
                ["Issue", "Where", "Reason given", "Review by"],
                [
                    [a["title"], a["asset"], a["reason"], _date(a["until"])]
                    for a in accepted
                ],
                [52 * mm, 34 * mm, 62 * mm, 26 * mm],
                s,
            )
        )

    resolved = snapshot.get("resolved", [])
    if resolved:
        story.append(Paragraph("Fixed since the last report", s["h1"]))
        story.append(
            _table(
                ["Issue", "Where", "Was", "Fixed on"],
                [
                    [r["title"], r["asset"], r["severity"].capitalize(), _date(r["fixed_at"])]
                    for r in resolved
                ],
                [70 * mm, 50 * mm, 26 * mm, 28 * mm],
                s,
            )
        )

    story.append(Paragraph("About this report", s["h1"]))
    notes = [
        f"Scan: {scan['mode']} scan finished {_date(scan['finished_at'])}. This is a snapshot of "
        "that moment; the situation may have changed since.",
        "Scoring: each issue is scored on how bad it is, how easy it is to exploit and how "
        f"exposed it is (scoring model version {snapshot['scoring_model_version']}). Fixed and "
        "accepted issues are not counted.",
        "A scan can only report what it found; it cannot prove that something is safe.",
    ]
    if scan["mode"] == "passive":
        notes.append("Passive scans look only at what the internet can already see.")
    if scan["status"] == "partial":
        notes.insert(
            1,
            "Some checks in this scan could not finish. Issues from those checks are neither "
            "confirmed as fixed nor ruled out; run another scan to complete the picture.",
        )
    story += [Paragraph(f"&bull; {_p(n)}", s["step"]) for n in notes]
    story.append(Spacer(1, 6))
    story.append(Paragraph(_p(f"Report ID: {snapshot['report_id']}"), s["small"]))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=22 * mm,
        title=_clean(f"Security posture report - {domain}"),
        author="Posture Scanner",
        invariant=1,  # same snapshot, same bytes: no embedded clock or random id
    )
    doc.build(story, canvasmaker=_numbered_canvas(_clean(f"{domain}  |  confidential")))
    return buffer.getvalue()