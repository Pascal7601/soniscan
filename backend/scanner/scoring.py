"""Scoring engine: pure functions, no framework imports.

Per finding:   score = severity weight x exploitability x exposure        (0..10)
Overall:       posture = round(100 x e^(-T / K)), where T is the total risk. Repeats of the same
               check across several assets count at `repeat_factor` after the first. Open Critical
               or High findings cap the result so a long list of passes cannot hide a dangerous one.
The constants live in a versioned database row (ScoringModel) so old reports stay reproducible.
"""

import math
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
GRADES = ("A", "B", "C", "D")  # anything below the D threshold is an F

TIER_FIX_NOW = "fix_now"
TIER_FIX_THIS_MONTH = "fix_this_month"
TIER_PLAN_LATER = "plan_later"


class ScoringError(ValueError):
    pass


@dataclass(frozen=True)
class ScoringParams:
    severity_weights: Mapping[str, float]
    decay_k: float
    repeat_factor: float
    grade_caps: Mapping[str, int]
    grade_bands: Mapping[str, int]  # minimum score for each of A, B, C, D
    tier_fix_now: float = 7.0
    tier_fix_this_month: float = 4.0

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ScoringParams":
        try:
            weights = {k: float(v) for k, v in data["severity_weights"].items()}
            caps = {k: int(v) for k, v in data.get("grade_caps", {}).items()}
            bands = {k: int(v) for k, v in data["grade_bands"].items()}
            params = cls(
                severity_weights=weights,
                decay_k=float(data["decay_k"]),
                repeat_factor=float(data["repeat_factor"]),
                grade_caps=caps,
                grade_bands=bands,
                tier_fix_now=float(data.get("tier_fix_now", 7.0)),
                tier_fix_this_month=float(data.get("tier_fix_this_month", 4.0)),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ScoringError(f"invalid scoring parameters: {exc}") from exc
        params._validate()
        return params

    def _validate(self) -> None:
        if set(self.severity_weights) != set(SEVERITIES):
            raise ScoringError(f"severity_weights must define exactly {SEVERITIES}")
        if any(w < 0 for w in self.severity_weights.values()):
            raise ScoringError("severity weights cannot be negative")
        if self.decay_k <= 0:
            raise ScoringError("decay_k must be positive")
        if not 0 <= self.repeat_factor <= 1:
            raise ScoringError("repeat_factor must be between 0 and 1")
        if set(self.grade_bands) != set(GRADES):
            raise ScoringError("grade_bands must define A, B, C and D")
        thresholds = [self.grade_bands[g] for g in GRADES]
        if thresholds != sorted(thresholds, reverse=True):
            raise ScoringError("grade thresholds must descend from A to D")
        if not set(self.grade_caps) <= set(SEVERITIES):
            raise ScoringError("grade_caps keys must be severities")
        if self.tier_fix_this_month > self.tier_fix_now:
            raise ScoringError("tier thresholds out of order")


# Version 1 of the model; must equal the row seeded by the database migration (tested).
DEFAULT_PARAMS = ScoringParams.from_dict(
    {
        "severity_weights": {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0},
        "decay_k": 40,
        "repeat_factor": 0.5,
        "grade_caps": {"critical": 69, "high": 79},
        "grade_bands": {"A": 90, "B": 80, "C": 70, "D": 60},
    }
)


@dataclass(frozen=True)
class FindingInput:
    check_key: str
    severity: str
    exploitability: float
    exposure: float


@dataclass(frozen=True)
class PostureResult:
    score: int
    grade: str
    total_risk: float
    capped_by: str | None  # "critical" or "high" when a cap lowered the score
    counts_by_tier: Mapping[str, int] = field(default_factory=dict)


def _round_half_up(value: float) -> int:
    return math.floor(value + 0.5)


def finding_score(
    severity: str, exploitability: float, exposure: float, params: ScoringParams = DEFAULT_PARAMS
) -> float:
    if severity not in params.severity_weights:
        raise ScoringError(f"unknown severity: {severity!r}")
    if not 0 <= exploitability <= 1:
        raise ScoringError("exploitability must be between 0 and 1")
    if not 0 <= exposure <= 1:
        raise ScoringError("exposure must be between 0 and 1")
    return round(params.severity_weights[severity] * exploitability * exposure, 2)


def tier(score: float, params: ScoringParams = DEFAULT_PARAMS) -> str:
    if score >= params.tier_fix_now:
        return TIER_FIX_NOW
    if score >= params.tier_fix_this_month:
        return TIER_FIX_THIS_MONTH
    return TIER_PLAN_LATER


def grade_for(score: int, params: ScoringParams = DEFAULT_PARAMS) -> str:
    for letter in GRADES:
        if score >= params.grade_bands[letter]:
            return letter
    return "F"


def posture(
    findings: Iterable[FindingInput], params: ScoringParams = DEFAULT_PARAMS
) -> PostureResult:
    """Overall score for a set of OPEN findings (callers exclude fixed and accepted ones)."""
    scores_by_check: dict[str, list[float]] = defaultdict(list)
    severities: set[str] = set()
    tiers = {TIER_FIX_NOW: 0, TIER_FIX_THIS_MONTH: 0, TIER_PLAN_LATER: 0}

    for f in findings:
        score = finding_score(f.severity, f.exploitability, f.exposure, params)
        scores_by_check[f.check_key].append(score)
        severities.add(f.severity)
        tiers[tier(score, params)] += 1

    total = 0.0
    for scores in scores_by_check.values():
        scores.sort(reverse=True)
        total += scores[0] + params.repeat_factor * sum(scores[1:])

    result = _round_half_up(100 * math.exp(-total / params.decay_k))

    capped_by = None
    for severity in ("critical", "high"):  # most severe present severity decides the cap
        if severity in severities and severity in params.grade_caps:
            cap = params.grade_caps[severity]
            if result > cap:
                result, capped_by = cap, severity
            break

    return PostureResult(
        score=result,
        grade=grade_for(result, params),
        total_risk=round(total, 2),
        capped_by=capped_by,
        counts_by_tier=tiers,
    )