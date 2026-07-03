# Releasing django-waf

How to cut a release for this package.

## TL;DR

```
branch  ->  PR  ->  review  ->  merge to main  ->  tag the merged commit  ->  CI publishes
```

The **tag is the trigger**. Pushing a tag of the form `v<semver>` runs the
publish workflow, which tests, builds, uploads to PyPI (OIDC trusted publishing,
no token), and creates a GitHub release. **Tagging is publishing. There is no
separate "publish" step and no undo.**

## Canonical flow

1. **Branch** off `main`:
   `release/<version>` (e.g. `release/1.0.2`).
2. **Bump** on the branch:
   - `pyproject.toml` under `[project]` version. This is the only place the
     version lives: `src/django_waf/__init__.py` reads `__version__` from
     package metadata at runtime, so there is no second string to keep in sync.
   - `CHANGELOG.md`: rename `[Unreleased]` to `[<version>] - <YYYY-MM-DD>`.
3. **Open a PR** to `main`. CI runs lint and tests. Get it reviewed. This is the
   gate: do not skip it.
4. **Merge to `main`** (squash or merge, per repo norm).
5. **Tag the merged commit on `main`** and push the tag:
   ```bash
   git checkout main && git pull
   git tag v<version>
   git push origin v<version>
   ```
6. **Watch the publish run** and confirm PyPI:
   ```bash
   gh run watch <run-id> --exit-status
   curl -s https://pypi.org/pypi/django-waf/json | python -c \
     "import sys,json;print(json.load(sys.stdin)['info']['version'])"
   ```

Tag the commit that is on `main`, not a feature branch. Tags point at commits,
not branches, so tagging a feature branch will publish, but it publishes code
that may never have been merged. Always tag after the merge.

## Tag format (strict)

`v<semver>`: just `v` then the version number. The publish workflow matches
`v*` and parses the version by stripping the leading `v`.

Examples: `v1.0.2`, `v1.1.0`, `v2.0.0`.

## Versioning (SemVer)

[Semantic Versioning](https://semver.org/). The package is past 1.0, so the
stability commitment applies:

- **Patch** (`1.0.1 -> 1.0.2`): bug fixes, doc-only changes, no API or behaviour
  change.
- **Minor** (`1.0.1 -> 1.1.0`): new public API, **any behaviour change** (even a
  safer one, such as a detector scoring differently), or a raised minimum
  dependency floor (e.g. Django).
- **Major** (`1.x -> 2.0`): breaking changes to any public surface: imports,
  settings names (`DJANGO_WAF_*`), model fields, management commands, template
  paths, signal signatures, or Redis key formats that consumers may depend on.

If in doubt between patch and minor, choose minor. Burning a version number is
free; shipping a behaviour change as a patch surprises consumers. A WAF has an
extra caveat: changes to detection thresholds, scoring weights, or default
settings alter what gets blocked in production, so they are behaviour changes
even when no code path "breaks".

## CHANGELOG (required for every release)

**A release MUST include a CHANGELOG entry for its version. No entry, no tag.**
The publish workflow's `resolve` job greps `CHANGELOG.md` for the version heading
and exits with an error if it is absent.

Format: [Keep a Changelog](https://keepachangelog.com/). Accumulate entries under
`## [Unreleased]` as you work; at release time rename that heading to
`## [<version>] - <YYYY-MM-DD>`. Subsections: Added / Changed / Fixed / Removed.

Call out behaviour changes explicitly, including ones that are "safer": a
consumer relying on the old behaviour still needs to know. That includes changes
to default thresholds, scoring weights, and anything that alters block or
challenge decisions.

## Django pin

The publish workflow's test job pins `Django~=5.2.0` (the package's minimum).
When you raise the minimum Django in `pyproject.toml`, update that pin in the
same PR, or the tagged build's test job can fail to resolve dependencies and
block the publish.

## Pre-tag checklist

Before pushing the tag (the irreversible step):

- [ ] `CHANGELOG.md` has a `[<version>] - <date>` entry (renamed from `[Unreleased]`).
- [ ] Behaviour changes and breaking changes called out in that CHANGELOG entry.
- [ ] Version bumped in `pyproject.toml`.
- [ ] Django pin in `.github/workflows/publish.yml` matches the package's minimum, if the floor changed.
- [ ] Tests pass locally and the package builds (`python -m build` at repo root).
- [ ] The PR is **merged to `main`** and you are tagging that commit.
- [ ] Tag format is `v<version>`.
- [ ] This exact version has never been published (PyPI rejects re-uploads).

## If something goes wrong

- **PyPI rejects the upload (version exists).** That version is permanently taken.
  Bump to the next patch and re-tag.
- **The test or build job fails after tagging.** Nothing was published (publish
  is the last job and depends on test and build). Fix on a new PR, merge, delete
  the bad tag (`git push --delete origin <tag>`), and re-tag the new commit with
  the **same** version (since nothing reached PyPI).
- **Published, but the code is not on `main`.** Open a PR from the release branch
  to `main` immediately and merge, so `main` reflects what is on PyPI. Avoid this
  by always tagging after the merge.

## Optional hardening

Consider adding a **manual approval gate** to the `publish` job via a protected
GitHub Environment (`pypi`), so "push tag" and "irreversibly upload to PyPI" are
decoupled: a human approves the upload after seeing test and build go green. The
workflow already declares `environment: pypi`; add a required-reviewer protection
rule to that environment to enable the gate.
