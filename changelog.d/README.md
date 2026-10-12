# changelog.d — one file per pull request

Do not edit the `## [Unreleased]` section of `CHANGELOG.md`. Every pull request
that changes what an operator or user sees adds its own fragment here instead,
so two pull requests in flight never conflict over the same lines.

Name it after the branch or topic: `changelog.d/<slug>.md`, for example
`changelog.d/tunnel-policy.md`. Use lower-case letters, digits and hyphens. The
name only decides the order of bullets within a heading in the release (C-locale
filename sort); it never appears in the CHANGELOG.

## Format

Keep-a-Changelog headings, each followed by bullets:

```markdown
### Added
- **The thing, in bold.** One or two user-facing lines about what it does.
  A wrapped line, or a nested `  - bullet`, is indented under its bullet.

### Fixed
- **What was wrong.** What happens now.
```

Allowed headings, in the order the release lists them:

`### Added`, `### Changed`, `### Deprecated`, `### Removed`, `### Fixed`,
`### Security`, `### Documentation`, `### Upgrade notes`

Use only the headings you need. Blank lines and `<!-- comments -->` are
ignored; any other line is refused. `make changelog-check` (or
`bash scripts/check-changelog-fragments.sh`, which CI runs) validates every
fragment.

## At release time

`scripts/changelog-assemble.sh X.Y.Z` merges every fragment (and anything still
under `[Unreleased]`) into a new `## [X.Y.Z] - YYYY-MM-DD` section, grouped by
heading, updates the compare links, and deletes the fragments. See
[docs/RELEASING.md](../docs/RELEASING.md).
