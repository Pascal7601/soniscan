from .types import Check

_CHECKS: dict[str, Check] = {}


def register[C: Check](check: C) -> C:
    if check.key in _CHECKS:
        raise ValueError(f"duplicate check key: {check.key}")
    _CHECKS[check.key] = check
    return check


def all_checks() -> list[Check]:
    return list(_CHECKS.values())


def passive_checks() -> list[Check]:
    """Checks safe to run against any domain without ownership proof."""
    return [c for c in _CHECKS.values() if not c.requires_verification]
