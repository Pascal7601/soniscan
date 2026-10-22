"""Check library: load and validate TOML definitions, sync them into the database as versions.

A definition whose content changes becomes a NEW version; old versions stay so historical
findings and reports keep the exact text they were produced with. Keys removed from the files are
deactivated, never deleted. Run `manage.py sync_check_library` as the owner role on each deploy.
"""

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

from django.db import transaction
from django.db.models import Max

from .models import SEVERITY_CHOICES, CheckDefinition

LIBRARY_DIR = Path(__file__).parent / "library"
_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")
_REQUIRED = (
    "key", "category", "requires_verification", "title", "severity", "exploitability",
    "effort", "explanation", "impact", "steps",
)  # fmt: skip


class LibraryError(Exception):
    pass


@dataclass
class SyncResult:
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    retired: list[str] = field(default_factory=list)
    unchanged: int = 0


def _validate(entry: dict[str, Any], source: str) -> dict[str, Any]:
    where = f"{source}: {entry.get('key', '<no key>')}"
    missing = [k for k in _REQUIRED if k not in entry]
    if missing:
        raise LibraryError(f"{where}: missing {', '.join(missing)}")
    if not _KEY_RE.match(entry["key"]):
        raise LibraryError(f"{where}: key must look like EMAIL_DMARC_MISSING")
    if entry["category"] not in CheckDefinition.Category.values:
        raise LibraryError(f"{where}: unknown category {entry['category']!r}")
    if entry["severity"] not in {value for value, _ in SEVERITY_CHOICES}:
        raise LibraryError(f"{where}: unknown severity {entry['severity']!r}")
    if entry["effort"] not in CheckDefinition.Effort.values:
        raise LibraryError(f"{where}: unknown effort {entry['effort']!r}")
    if not isinstance(entry["requires_verification"], bool):
        raise LibraryError(f"{where}: requires_verification must be true or false")
    exploitability = entry["exploitability"]
    if isinstance(exploitability, bool) or not isinstance(exploitability, int | float):
        raise LibraryError(f"{where}: exploitability must be a number")
    if not 0 <= exploitability <= 1:
        raise LibraryError(f"{where}: exploitability must be between 0 and 1")
    steps = entry["steps"]
    if not isinstance(steps, list) or not steps or not all(isinstance(s, str) and s for s in steps):
        raise LibraryError(f"{where}: steps must be a non-empty list of text")
    for name in ("title", "explanation", "impact"):
        if not isinstance(entry[name], str) or not entry[name].strip():
            raise LibraryError(f"{where}: {name} must be non-empty text")
    return {
        "key": entry["key"],
        "category": entry["category"],
        "requires_verification": entry["requires_verification"],
        "title": entry["title"].strip(),
        "severity": entry["severity"],
        "exploitability": round(float(exploitability), 2),
        "effort": entry["effort"],
        "owner": str(entry.get("owner", "")).strip(),
        "explanation": " ".join(entry["explanation"].split()),
        "impact": " ".join(entry["impact"].split()),
        "steps": list(steps),
        "links": list(entry.get("links", [])),
    }


def load_library(directory: Path = LIBRARY_DIR) -> dict[str, dict[str, Any]]:
    definitions: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.glob("*.toml")):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise LibraryError(f"{path.name}: invalid TOML: {exc}") from exc
        for entry in data.get("checks", []):
            definition = _validate(entry, path.name)
            if definition["key"] in definitions:
                raise LibraryError(f"{path.name}: duplicate key {definition['key']}")
            definitions[definition["key"]] = definition
    return definitions


def _content_hash(definition: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(definition, sort_keys=True).encode()).hexdigest()


@transaction.atomic
def sync_check_library(directory: Path = LIBRARY_DIR) -> SyncResult:
    definitions = load_library(directory)
    result = SyncResult()

    latest: dict[str, CheckDefinition] = {}
    for row in CheckDefinition.objects.order_by("check_key", "version"):
        latest[row.check_key] = row  # ascending version, so the last one wins

    for key, d in definitions.items():
        digest = _content_hash(d)
        current = latest.get(key)
        if current is not None and current.content_hash == digest and current.is_active:
            result.unchanged += 1
            continue
        CheckDefinition.objects.create(
            check_key=key,
            version=(current.version + 1) if current else 1,
            category=d["category"],
            requires_verification=d["requires_verification"],
            title=d["title"],
            severity_base=d["severity"],
            exploitability_base=Decimal(str(d["exploitability"])),
            plain_explanation=d["explanation"],
            why_it_matters=d["impact"],
            fix_steps=d["steps"],
            effort=d["effort"],
            owner_hint=d["owner"],
            reference_links=d["links"],
            content_hash=digest,
        )
        (result.updated if current else result.created).append(key)

    for key in latest.keys() - definitions.keys():
        if CheckDefinition.objects.filter(check_key=key, is_active=True).update(is_active=False):
            result.retired.append(key)

    # Earlier versions of a key are superseded; keep them readable but never selected for new work.
    for key in result.updated:
        newest = CheckDefinition.objects.filter(check_key=key).aggregate(Max("version"))[
            "version__max"
        ]
        CheckDefinition.objects.filter(check_key=key, version__lt=newest).update(is_active=False)
    return result