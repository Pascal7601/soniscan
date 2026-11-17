"""The renderer is pure, so these tests need no database."""

import re

import pytest

from apps.reports import pdf


def finding(i=0, **overrides):
    base = {
        "finding_id": f"f{i}",
        "check_key": "EMAIL_DMARC_MISSING",
        "title": "Fake emails in your company's name",
        "asset": "acme.example",
        "severity": "medium",
        "score": 3.2,
        "tier": "plan_later",
        "plain_explanation": "Anyone can send email that looks like it came from you.",
        "why_it_matters": "Customers may be tricked into paying a fake invoice.",
        "fix_steps": ["Add a DMARC record.", "Review the reports."],
        "effort": "minutes",
        "owner_hint": "Whoever manages your domain",
        "first_seen_at": "2026-10-01T10:00:00+00:00",
        "reopened_count": 0,
    }
    return {**base, **overrides}


def snapshot(**overrides):
    base = {
        "version": 1,
        "report_id": "11111111-2222-3333-4444-555555555555",
        "generated_at": "2026-11-06T09:30:00+00:00",
        "organisation": "Acme Ltd",
        "domain": "acme.example",
        "scan": {
            "id": "s1",
            "mode": "passive",
            "status": "succeeded",
            "finished_at": "2026-11-06T09:29:00+00:00",
        },
        "scoring_model_version": 1,
        "posture": {
            "score": 88,
            "grade": "B",
            "capped_by": None,
            "total_risk": 5.2,
            "counts_by_tier": {"fix_now": 0, "fix_this_month": 0, "plan_later": 1},
        },
        "previous": None,
        "findings": [finding()],
        "accepted": [],
        "resolved": [],
    }
    return {**base, **overrides}


def pages(data: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page(?!s)", data))


def test_renders_a_pdf():
    data = pdf.render_pdf(snapshot())
    assert data.startswith(b"%PDF-")
    assert pages(data) == 1


def test_the_same_snapshot_gives_the_same_bytes():
    assert pdf.render_pdf(snapshot()) == pdf.render_pdf(snapshot())


def test_a_clean_report_renders():
    clean = snapshot(
        findings=[],
        posture={
            "score": 100,
            "grade": "A",
            "capped_by": None,
            "total_risk": 0,
            "counts_by_tier": {"fix_now": 0, "fix_this_month": 0, "plan_later": 0},
        },
    )
    assert pdf.render_pdf(clean).startswith(b"%PDF-")


def test_a_long_report_paginates():
    many = snapshot(findings=[finding(i, asset=f"host{i}.acme.example") for i in range(60)])
    assert pages(pdf.render_pdf(many)) > 3


def test_every_optional_section_renders():
    full = snapshot(
        previous={"generated_at": "2026-10-12T08:00:00+00:00", "score": 60, "grade": "D"},
        scan={
            "id": "s1",
            "mode": "passive",
            "status": "partial",
            "finished_at": "2026-11-06T09:29:00+00:00",
        },
        accepted=[
            {
                "title": "Version shown",
                "asset": "www.acme.example",
                "severity": "low",
                "reason": "Behind a firewall",
                "until": "2027-03-01T00:00:00+00:00",
            }
        ],
        resolved=[
            {
                "title": "Certificate expiring",
                "asset": "acme.example",
                "severity": "high",
                "fixed_at": "2026-10-20T00:00:00+00:00",
            }
        ],
    )
    assert pdf.render_pdf(full).startswith(b"%PDF-")


@pytest.mark.parametrize(
    "text",
    [
        "<b>bold</b> & <i>unclosed",
        "<script>alert(1)</script>",
        "arrow \u2192 and emoji \U0001f600 and kanji \u6f22\u5b57",
        "control\x00chars\x1fhere",
        "</para><para>",
    ],
)
def test_hostile_text_cannot_break_rendering(text):
    snap = snapshot(
        domain="acme.example",
        organisation=text,
        findings=[finding(title=text, asset=text, plain_explanation=text, fix_steps=[text])],
        accepted=[
            {
                "title": text,
                "asset": text,
                "severity": "low",
                "reason": text,
                "until": "2027-03-01T00:00:00+00:00",
            }
        ],
    )
    assert pdf.render_pdf(snap).startswith(b"%PDF-")


def test_markup_characters_are_escaped():
    assert pdf._p("<b>&") == "&lt;b&gt;&amp;"


def test_characters_the_font_cannot_draw_become_question_marks():
    assert pdf._clean("a\u2192b\x00") == "a?b"
    assert pdf._clean("caf\u00e9 \u2014 ok") == "caf\u00e9 \u2014 ok"  # in Windows-1252


def test_an_unknown_snapshot_version_is_refused():
    with pytest.raises(pdf.ReportRenderError):
        pdf.render_pdf(snapshot(version=99))