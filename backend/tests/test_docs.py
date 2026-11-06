"""Keeps the documentation honest: fails when the code gains something the docs do not mention,
or when the docs point at a file that no longer exists.

Each app documents itself in apps/<app>/README.md and the scanner in scanner/README.md.
"""

import importlib
import re
from pathlib import Path

import pytest
from django.apps import apps as django_apps

BACKEND = Path(__file__).resolve().parent.parent
APPS = ["core", "accounts", "domains", "scans", "findings", "runner"]
API_APPS = ["accounts", "domains", "scans", "findings"]


def readme(app: str) -> str:
    return (BACKEND / "apps" / app / "README.md").read_text()


def all_docs() -> dict[str, str]:
    docs = {app: readme(app) for app in APPS}
    docs["scanner"] = (BACKEND / "scanner" / "README.md").read_text()
    return docs


@pytest.mark.parametrize("app", APPS)
def test_every_app_has_a_readme(app):
    assert (BACKEND / "apps" / app / "README.md").is_file()


def test_the_scanner_has_a_readme():
    assert (BACKEND / "scanner" / "README.md").is_file()


@pytest.mark.parametrize("app", APPS)
def test_every_table_is_documented(app):
    text = readme(app)
    missing = [m._meta.db_table for m in django_apps.get_app_config(app).get_models()
               if m._meta.db_table not in text]  # fmt: skip
    assert not missing, f"apps/{app}/README.md does not mention tables: {missing}"


@pytest.mark.parametrize("app", APPS)
def test_every_constraint_and_index_is_documented(app):
    text = readme(app)
    names = [c.name for m in django_apps.get_app_config(app).get_models()
             for c in (*m._meta.constraints, *m._meta.indexes)]  # fmt: skip
    missing = [n for n in names if n not in text]
    assert not missing, f"apps/{app}/README.md does not mention: {missing}"


@pytest.mark.parametrize("app", API_APPS)
def test_every_endpoint_is_documented(app):
    text = readme(app)
    module = importlib.import_module(f"apps.{app}.api.urls")
    missing = []
    for pattern in module.urlpatterns:
        route = "/api/v1/" + re.sub(r"<\w+:(\w+)>", r"{\1}", str(pattern.pattern))
        if route not in text:
            missing.append(route)
    assert not missing, f"apps/{app}/README.md does not mention endpoints: {missing}"


def test_every_celery_task_is_documented():
    from config.celery import app as celery_app

    celery_app.loader.import_default_modules()
    names = [n for n in celery_app.tasks if n.startswith("runner.")]
    assert names
    missing = [n for n in names if n not in readme("runner")]
    assert not missing, f"apps/runner/README.md does not mention tasks: {missing}"


def test_every_audit_event_is_in_the_core_catalogue():
    events: set[str] = set()
    for path in (BACKEND / "apps").rglob("*.py"):
        if "migrations" in path.parts:
            continue
        events |= set(re.findall(r'action="([a-z_]+\.[a-z_]+)"', path.read_text()))
    assert events
    missing = sorted(e for e in events if f"`{e}`" not in readme("core"))
    assert not missing, f"apps/core/README.md audit catalogue is missing: {missing}"


def test_every_check_library_key_is_documented_in_findings():
    from apps.findings.library import load_library

    missing = [k for k in load_library() if k not in readme("findings")]
    assert not missing, f"apps/findings/README.md does not list library keys: {missing}"


def test_every_scanner_module_and_check_is_documented():
    import scanner.checks  # noqa: F401  (registers checks)
    from scanner.registry import all_checks

    text = (BACKEND / "scanner" / "README.md").read_text()
    modules = [p.name for p in (BACKEND / "scanner").rglob("*.py")]
    missing = [m for m in modules if m not in text]
    assert not missing, f"scanner/README.md does not mention files: {missing}"
    for check in all_checks():
        assert check.key in text, f"scanner/README.md does not mention check {check.key}"
        for key in check.emits:
            assert key in text, f"scanner/README.md does not mention finding {key}"


@pytest.mark.parametrize("name", [*APPS, "scanner"])
def test_documented_files_exist(name):
    """Every `file.py` / `dir/file.toml` named in backticks must exist somewhere sensible."""
    text = all_docs()[name]
    repo = BACKEND.parent
    own = BACKEND / "scanner" if name == "scanner" else BACKEND / "apps" / name
    roots = [own, BACKEND / "apps", BACKEND, repo]  # relative to the app, apps/, backend/ or the repo
    missing = []
    for token in set(re.findall(r"`([\w./-]+\.(?:py|toml|md|sql|yml|yaml))`", text)):
        path = Path(token.split("::")[0])
        if any((root / path).exists() for root in roots):
            continue
        if "/" not in token and any(BACKEND.rglob(path.name)):
            continue  # a bare file name that exists elsewhere in the backend
        missing.append(token)
    assert not missing, f"{name} docs mention files that do not exist: {missing}"