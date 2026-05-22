# Contributing to django-waf

Thanks for your interest in contributing. This guide covers the development
workflow, code standards, and how to submit changes.

## Development Setup

```bash
git clone git@github.com:nigelcopley/django-waf.git
cd django-waf
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,celery]"
```

Verify everything works:

```bash
pytest
ruff check src/ tests/
ruff format --check src/ tests/
```

## Running Tests

```bash
# Full suite
pytest

# With coverage
pytest --cov=src --cov-report=term-missing

# Single test file or class
pytest tests/test_services.py::TestDetectUnsolvedChallenges
```

Coverage must stay at or above **90%**. New features should include tests.

## Code Style

- **Linter/formatter**: ruff (configured in `pyproject.toml`)
- **Language**: British English in documentation and user-facing strings
  (organisation, behaviour, defence, licence)
- **Type hints**: use `from __future__ import annotations` and type all
  function signatures
- **Imports**: lazy imports inside function bodies for Celery task compatibility
  and to avoid circular imports
- **No emojis** in code, comments, or documentation

Run before committing:

```bash
ruff check src/ tests/ --fix
ruff format src/ tests/
```

## Architecture Conventions

- **Services are functions, not classes** — business logic lives in
  `src/icv_waf/services/` as module-level functions
- **Settings are namespaced** — all settings use the `ICV_WAF_*` prefix and
  are defined in `src/icv_waf/conf.py` with sensible defaults
- **Fail-open design** — if Redis is unavailable or an error occurs during
  evaluation, the request passes through. Never block legitimate traffic
  due to infrastructure failure
- **Signals for extensibility** — use Django signals for side effects that
  consuming projects might want to hook into
- **No external package dependencies beyond Django, django-redis, and httpx** —
  optional features (Celery, GeoIP) use optional dependencies

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type: description

# Types: feat, fix, refactor, test, docs, ci, chore
# Examples:
# feat: add path-based threat scoring
# fix: handle empty ip_address in challenge view
# docs: update settings reference table
```

## Pull Request Process

1. Fork the repository and create a feature branch from `main`
2. Make your changes with tests
3. Ensure `pytest`, `ruff check`, and `ruff format --check` all pass
4. Coverage must remain at or above 90%
5. Write a clear PR description explaining what and why
6. One approval required before merge

## Adding a New Setting

1. Add the setting with a default in `src/icv_waf/conf.py`
2. Use it via `from icv_waf import conf; conf.ICV_WAF_YOUR_SETTING`
3. Add it to the settings table in `README.md`
4. Add a test that exercises the setting

## Generating Migrations

This package ships no `manage.py`, and `tests/settings.py` disables migrations
so the test database builds straight from the models. To author or update
migrations after a model change, use the committed helper:

```bash
python make_migrations.py            # write/update migrations
python make_migrations.py --check    # CI-style: fail if migrations are missing
```

Commit the generated file under `src/icv_waf/migrations/` alongside the model
change.

## Adding a New Anomaly Detector

1. Add the detector function in `src/icv_waf/services/anomaly_detector.py`
2. Use `_get_or_create_auto_rule()` for rule creation (prevents duplicates)
3. Use `_emit_anomaly_signal()` for observability
4. Wire it into `run_all_detectors()` and add the key to the return dict
5. Add an `AnomalyType` enum value in `src/icv_waf/enums.py`
6. Add tests covering: detection, skip-when-already-exists, edge cases

## Reporting Issues

Open an issue at https://github.com/nigelcopley/django-waf/issues with:

- django-waf version (`python -c "import icv_waf; print(icv_waf.__version__)"`)
- Django version
- Python version
- Steps to reproduce
- Expected vs actual behaviour
