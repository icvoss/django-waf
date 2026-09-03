#!/usr/bin/env python3
"""Guard: every BR- rule id cited in src/ must be defined in the spec.

See scripts/README.md for the incident this guards against, the control
design, and how to run it locally.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

CITATION_PATTERN = re.compile(r"BR-[A-Z]+-\d+[a-z]?")
HEADING_PATTERN = re.compile(r"(?m)^### (BR-[A-Z]+-\d+[a-z]?)\b")

# Directory names to skip when walking src/. Not expected to exist on a
# fresh checkout, but a dirty runner or local working tree can carry them.
# Build artefacts are excluded by suffix rather than by exact name because
# the generated directory is named after the distribution: this repo
# produces src/django_waf.egg-info/, which is gitignored (.gitignore line
# 3) and untracked. Reading it is not merely redundant, it makes the
# guard's own result depend on whether anyone has run an editable install
# locally: PKG-INFO embeds the README, so the settings table's
# BR-EVAL-012 reference appeared as a 67th citation on a built tree and
# not at all on a clean one. A guard whose counts move with local build
# state cannot be used to tell a real citation from a stale one.
EXCLUDED_DIR_NAMES = {"__pycache__", ".git"}
EXCLUDED_DIR_SUFFIXES = (".egg-info", ".dist-info")

# Known-present items asserted before any absence is trusted (issue #133).
# A rule id known to exist on the spec side, including one with the
# lowercase suffix, since a regex that drops the suffix would silently
# under-match without this control catching it.
CONTROL_RULE_IDS = ("BR-UA-002", "BR-EVAL-001", "BR-ANOM-002b")
# A citation known to exist on the source side.
CONTROL_CITATION = "BR-UA-002"


def _default_spec_dir() -> Path:
    """Locate the umbrella spec for the normal workspace layout.

    Resolved from the repo's MAIN worktree rather than from this file's
    own path. Counting parents from __file__ is correct only in a plain
    checkout: under the repo's own worktree convention the script lives at
    .claude/worktrees/<slug>/scripts/, so four parents up lands inside
    .claude/ and the guard reports the spec as missing. It fails loudly
    rather than passing when that happens, which is the intended
    behaviour, but the default should simply work from a worktree, since
    worktrees are how work is normally split out here.

    git rev-parse --path-format=absolute --git-common-dir returns the
    shared .git directory for both a checkout and any of its worktrees,
    whose parent is always the main checkout.
    """
    repo_root = Path(__file__).resolve().parent.parent
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            repo_root = Path(result.stdout.strip()).parent
    except (OSError, subprocess.SubprocessError):
        pass
    return repo_root.parent.parent / "docs" / "specs" / "django-waf"


DEFAULT_SPEC_DIR = _default_spec_dir()


class GuardError(Exception):
    """Raised for any condition that must fail the guard, control or real."""


def iter_src_files(src_dir: Path):
    for root, dirnames, filenames in os.walk(src_dir):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_NAMES and not d.endswith(EXCLUDED_DIR_SUFFIXES)]
        for filename in filenames:
            yield Path(root) / filename


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def collect_citations(src_dir: Path) -> set[str]:
    if not src_dir.is_dir():
        raise GuardError(f"src directory does not exist: {src_dir}")
    citations: set[str] = set()
    for path in iter_src_files(src_dir):
        try:
            text = read_text(path)
        except UnicodeDecodeError as exc:
            # Every file under src/ is text at the time of writing; a binary
            # file appearing later is not silently skipped.
            raise GuardError(f"could not read {path} as UTF-8 text") from exc
        citations |= set(CITATION_PATTERN.findall(text))
    return citations


def collect_rules_and_headings(spec_dir: Path) -> tuple[set[str], set[str]]:
    rules: set[str] = set()
    headings: set[str] = set()
    for path in sorted(spec_dir.glob("*.md")):
        text = read_text(path)
        rules |= set(CITATION_PATTERN.findall(text))
        headings |= set(HEADING_PATTERN.findall(text))
    return rules, headings


def resolve_spec_commit(spec_dir: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(spec_dir), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def run_controls(citations: set[str], rules: set[str], headings: set[str]) -> None:
    """Assert known-present items on both sides before trusting any absence.

    Both failure directions matter equally (issue #133): if the spec side
    silently returns nothing, every citation reports as dangling; if the
    citation side silently returns nothing, the guard passes having checked
    nothing. Either must error, never pass quietly.
    """
    for rule_id in CONTROL_RULE_IDS:
        if rule_id not in rules:
            raise GuardError(
                f"control failed: {rule_id} not found on the spec side. "
                "The spec directory is missing, empty, or unreadable: "
                "treat every 'dangling' result below as untrustworthy."
            )
    if CONTROL_CITATION not in citations:
        raise GuardError(
            "control failed: citation side empty (expected "
            f"{CONTROL_CITATION} in src/). The src directory is missing, "
            "empty, or the extraction pattern stopped matching: a zero "
            "dangling result below would be a vacuous pass, not a real one."
        )
    if not headings:
        raise GuardError(
            "control failed: the heading regex matched no '### BR-...' "
            "headings in the spec. Either the spec files are missing "
            "their expected heading format, or the spec directory is wrong."
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--src",
        type=Path,
        default=Path("src"),
        help="Path to the src/ directory to scan for BR- citations (default: src)",
    )
    parser.add_argument(
        "--spec-dir",
        type=Path,
        default=None,
        help=(
            "Path to the umbrella spec directory (docs/specs/django-waf). "
            "Falls back to $DJANGO_WAF_SPEC_DIR, then the local default "
            "'../../docs/specs/django-waf' relative to this repo."
        ),
    )
    require_group = parser.add_mutually_exclusive_group()
    require_group.add_argument(
        "--require-spec",
        dest="require_spec",
        action="store_true",
        default=True,
        help="Fail if the spec directory is missing or empty (default).",
    )
    require_group.add_argument(
        "--allow-missing-spec",
        dest="require_spec",
        action="store_false",
        help=(
            "Exit 0 without checking if the spec directory is missing. "
            "NOT for CI use: this is exactly the vacuous-pass failure "
            "issue #133 was filed about. For local use only, when the "
            "umbrella checkout is deliberately absent."
        ),
    )
    args = parser.parse_args()

    spec_dir = args.spec_dir or (
        Path(os.environ["DJANGO_WAF_SPEC_DIR"]) if "DJANGO_WAF_SPEC_DIR" in os.environ else DEFAULT_SPEC_DIR
    )
    spec_dir = spec_dir.resolve()
    src_dir = args.src.resolve()

    spec_files = sorted(spec_dir.glob("*.md")) if spec_dir.is_dir() else []

    if not spec_files:
        message = (
            f"spec directory has no spec files: {spec_dir}\n"
            "The umbrella checkout (docs/specs/django-waf) is absent, "
            "empty, or the path is wrong. This is precisely the "
            "vacuous-pass failure issue #133 was filed about: a check "
            "that cannot see the spec must not report zero dangling "
            "citations as if it had verified anything."
        )
        if args.require_spec:
            print(f"FAIL: {message}", file=sys.stderr)
            return 1
        print(f"SKIP (--allow-missing-spec): {message}")
        return 0

    try:
        citations = collect_citations(src_dir)
        rules, headings = collect_rules_and_headings(spec_dir)
        run_controls(citations, rules, headings)
    except GuardError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    commit = resolve_spec_commit(spec_dir)
    print(f"spec dir: {spec_dir}" + (f" @ {commit}" if commit else ""))
    print(f"src dir:  {src_dir}")
    print("controls OK (known-present rule ids incl. suffixed id, known-present citation, heading pattern)")
    print(
        f"citations={len(citations)} rules={len(rules)} headings={len(headings)} "
        f"reconcile={len(rules) == len(headings)}"
    )

    dangling = sorted(citations - rules)
    print("dangling:", dangling or "NONE")

    mentioned_no_heading = sorted(rules - headings)
    print("mentioned but no heading:", mentioned_no_heading or "none")

    if dangling:
        print(
            f"FAIL: {len(dangling)} citation(s) reference rule ids not defined in the spec (see 'dangling' above).",
            file=sys.stderr,
        )
        return 1

    print("PASS: every BR- citation in src/ is defined in the spec.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
