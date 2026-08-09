# Pull request

## What and why

Describe the change and the problem it solves. Link the issue if one
exists.

## Checklist

- [ ] Tests added or updated for the change (see CONTRIBUTING.md)
- [ ] `ruff check` and `ruff format --check` pass locally
- [ ] CHANGELOG.md has an entry under Unreleased
- [ ] If this PR ratifies or amends an ADR, every artefact named in its
      **Affects** field has a diff here, or a linked follow-up issue.
      Deferring part of a sweep is fine; leaving it unstated is not
      (project-standards LESSONS.md, Trap 30)
- [ ] No migration was generated with icv-core installed (packages with
      an optional icv-core dependency only; see the repo's docs)
- [ ] Breaking changes are called out explicitly below

## Breaking changes

None, or describe them.
