import pytest

from scanner import scoring
from scanner.scoring import DEFAULT_PARAMS, FindingInput, ScoringError, ScoringParams


def f(key, severity, exploitability=1.0, exposure=1.0):
    return FindingInput(key, severity, exploitability, exposure)


# ---- per-finding score -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "exploitability", "exposure", "expected"),
    [
        ("critical", 1.0, 1.0, 10.0),
        ("medium", 0.8, 1.0, 3.2),
        ("medium", 0.5, 1.0, 2.0),
        ("high", 0.5, 0.4, 1.4),
        ("low", 1.0, 1.0, 2.0),
        ("info", 1.0, 1.0, 0.0),
    ],
)
def test_finding_score(severity, exploitability, exposure, expected):
    assert scoring.finding_score(severity, exploitability, exposure) == expected


@pytest.mark.parametrize(
    ("severity", "exploitability", "exposure"),
    [("catastrophic", 1, 1), ("high", 1.1, 1), ("high", -0.1, 1), ("high", 1, 2)],
)
def test_finding_score_rejects_invalid_input(severity, exploitability, exposure):
    with pytest.raises(ScoringError):
        scoring.finding_score(severity, exploitability, exposure)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (10, "fix_now"),
        (7.0, "fix_now"),
        (6.99, "fix_this_month"),
        (4.0, "fix_this_month"),
        (3.99, "plan_later"),
        (0, "plan_later"),
    ],
)
def test_tier_boundaries(score, expected):
    assert scoring.tier(score) == expected


# ---- posture: the worked example from the design document --------------------------------------


def test_design_document_worked_example():
    findings = [
        f("SVC_RDP_EXPOSED", "critical", 1.0, 1.0),  # 10.0
        f("EMAIL_DMARC_MONITOR_ONLY", "medium", 0.8, 1.0),  # 3.2
        f("TLS_CERT_EXPIRING", "medium", 0.5, 1.0),  # 2.0
    ]
    result = scoring.posture(findings)
    assert result.total_risk == 15.2
    assert result.score == 68
    assert result.grade == "D"
    assert result.counts_by_tier == {"fix_now": 1, "fix_this_month": 0, "plan_later": 2}


def test_fixing_the_critical_finding_lifts_the_score():
    findings = [
        f("EMAIL_DMARC_MONITOR_ONLY", "medium", 0.8, 1.0),
        f("TLS_CERT_EXPIRING", "medium", 0.5, 1.0),
    ]
    result = scoring.posture(findings)
    assert result.total_risk == 5.2
    assert result.score == 88
    assert result.grade == "B"


def test_no_findings_is_a_perfect_score():
    result = scoring.posture([])
    assert (result.score, result.grade, result.total_risk, result.capped_by) == (100, "A", 0, None)


# ---- caps ---------------------------------------------------------------------------------------


def test_one_low_impact_critical_still_caps_the_grade_at_d():
    result = scoring.posture([f("X", "critical", 0.3, 0.4)])  # score 1.2 -> raw 97
    assert result.score == 69
    assert result.grade == "D"
    assert result.capped_by == "critical"


def test_high_finding_caps_at_c():
    result = scoring.posture([f("X", "high", 0.3, 0.4)])
    assert (result.score, result.grade, result.capped_by) == (79, "C", "high")


def test_cap_is_not_reported_when_it_changes_nothing():
    result = scoring.posture([f("A", "critical"), f("B", "critical"), f("C", "critical")])
    assert result.score < 69
    assert result.capped_by is None


# ---- repeats ------------------------------------------------------------------------------------


def test_repeats_of_the_same_check_count_at_half_after_the_first():
    same_check = scoring.posture([f("MISSING_HEADER", "medium", 0.5, 1.0)] * 3)  # 2 + 1 + 1
    assert same_check.total_risk == 4.0
    different_checks = scoring.posture([f(f"K{i}", "medium", 0.5, 1.0) for i in range(3)])
    assert different_checks.total_risk == 6.0


def test_the_highest_scoring_instance_counts_in_full():
    result = scoring.posture([f("K", "low", 1, 0.4), f("K", "high", 1, 1)])  # 0.8 and 7.0
    assert result.total_risk == 7.4  # 7.0 + 0.5 * 0.8


# ---- properties ---------------------------------------------------------------------------------


def test_adding_a_finding_never_improves_the_score():
    base = [f("A", "medium", 0.8), f("B", "low", 1.0)]
    previous = scoring.posture(base).score
    for extra in [f("C", "info"), f("A", "low"), f("D", "high", 0.3, 0.4), f("E", "critical")]:
        current = scoring.posture([*base, extra]).score
        assert current <= previous
        previous = current


@pytest.mark.parametrize("count", [0, 1, 5, 50, 500])
def test_score_is_always_between_0_and_100(count):
    result = scoring.posture([f(f"K{i}", "critical") for i in range(count)])
    assert 0 <= result.score <= 100


def test_posture_is_deterministic_and_order_independent():
    findings = [f("A", "high", 0.5), f("B", "medium"), f("A", "low"), f("C", "critical", 0.2, 0.7)]
    assert scoring.posture(findings) == scoring.posture(list(reversed(findings)))


@pytest.mark.parametrize(
    ("score", "grade"),
    [
        (100, "A"),
        (90, "A"),
        (89, "B"),
        (80, "B"),
        (79, "C"),
        (70, "C"),
        (69, "D"),
        (60, "D"),
        (59, "F"),
    ],
)
def test_grade_bands(score, grade):
    assert scoring.grade_for(score) == grade


# ---- parameters ---------------------------------------------------------------------------------


def test_params_round_trip_from_a_dict():
    data = {
        "severity_weights": {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0},
        "decay_k": 40,
        "repeat_factor": 0.5,
        "grade_caps": {"critical": 69},
        "grade_bands": {"A": 90, "B": 80, "C": 70, "D": 60},
    }
    assert ScoringParams.from_dict(data).grade_caps == {"critical": 69}


@pytest.mark.parametrize(
    "change",
    [
        {"decay_k": 0},
        {"repeat_factor": 1.5},
        {"severity_weights": {"critical": 10}},
        {"grade_bands": {"A": 60, "B": 70, "C": 80, "D": 90}},
        {"grade_caps": {"spicy": 10}},
        {"decay_k": "not a number"},
    ],
)
def test_invalid_params_are_rejected(change):
    data = {
        "severity_weights": {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0},
        "decay_k": 40,
        "repeat_factor": 0.5,
        "grade_caps": {},
        "grade_bands": {"A": 90, "B": 80, "C": 70, "D": 60},
        **change,
    }
    with pytest.raises(ScoringError):
        ScoringParams.from_dict(data)


def test_missing_keys_are_a_scoring_error_not_a_keyerror():
    with pytest.raises(ScoringError):
        ScoringParams.from_dict({})


def test_defaults_match_the_design_document():
    assert DEFAULT_PARAMS.decay_k == 40
    assert DEFAULT_PARAMS.grade_caps == {"critical": 69, "high": 79}