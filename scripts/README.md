# scripts/

## check_br_citations.py

Guards against a specific defect class: source code cites a `BR-XXX-NNN`
business-rule id as the authority for its behaviour, and the rule does not
actually exist in the spec. See issue #133 for the full history: two
confirmed occurrences (`BR-UA-002`, `BR-UA-004`) went unnoticed until
someone happened to change the code they governed and found there was no
spec text to amend, and a third (`BR-TEL-004`, should have been
`BR-TEL-003`) was found independently by a different session. Neither was
caught by a check.

### What it checks

Extracts every `BR-[A-Z]+-\d+[a-z]?` citation from every file under `src/`
(the lowercase suffix, e.g. `BR-ANOM-002b`, is a real pattern in this
spec, not test noise) and asserts each one is defined by a matching
`### BR-...` heading in the umbrella spec at `docs/specs/django-waf/*.md`.
Any citation with no matching rule (a "dangling" citation) fails the
guard.

### Why the controls exist

The citations live in this repo; the rules live in a separate umbrella
repo. That split makes the check falsifiable in two symmetric,
opposite-looking ways, and a run that hits either one silently is worse
than no check at all:

- If the **spec side** returns nothing (wrong path, umbrella checkout
  absent, empty directory), every citation looks dangling and the guard
  fails, but for the wrong reason: not because the code is wrong, but
  because the check could not see the spec. This happened for real: a
  session ran an ad hoc check from inside this repo, the spec-side lookup
  silently returned zero rules, and it reported "63 dangling rules",
  which was completely wrong.
- If the **citation side** returns nothing (wrong path, empty src,
  extraction pattern stopped matching), zero dangling citations are
  reported and the guard passes, having checked nothing at all.

Both failure modes are unfalsifiable without a control: a check that
cannot tell "there is genuinely nothing wrong" from "I could not see
anything" is not evidence either way. So before this script trusts any
absence, it asserts:

- at least one rule id known to exist in the spec (three are checked,
  including a suffixed one, since a regex that silently dropped the
  suffix would otherwise under-match without anything noticing),
- at least one citation known to exist in `src/`,
- that the heading regex matched at least one `### BR-...` heading.

If any control fails, the script exits non-zero with a message naming
which control failed and why the result below it cannot be trusted. A
control failure is never allowed to read as a pass, and the default CLI
behaviour requires a real, non-empty spec directory: `--allow-missing-spec`
exists for local convenience only and is never the default.

### Running it locally

From a checkout where the umbrella repo is cloned as a sibling of
`public/` (the normal layout, `~/Projects/oss/public/django-waf` next to
`~/Projects/oss/docs/specs/django-waf`), no arguments are needed:

```sh
python3 scripts/check_br_citations.py
```

To point at a different umbrella checkout, pass `--spec-dir` or set
`DJANGO_WAF_SPEC_DIR`:

```sh
python3 scripts/check_br_citations.py --spec-dir /path/to/icv-oss-umbrella/docs/specs/django-waf
DJANGO_WAF_SPEC_DIR=/path/to/icv-oss-umbrella/docs/specs/django-waf python3 scripts/check_br_citations.py
```

`--src` overrides which directory is scanned for citations (default
`src`). Both flags accept relative or absolute paths.

Standard library only, no dependencies. Python 3.

### Exit codes

- `0`: every citation resolved to a spec rule, and all controls passed.
- `1`: a dangling citation was found, a control failed, or the spec
  directory was missing or empty (and `--allow-missing-spec` was not
  passed).
