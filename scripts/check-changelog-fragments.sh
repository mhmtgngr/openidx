#!/usr/bin/env bash
#
# check-changelog-fragments.sh — every changelog.d/ fragment must be one the
# release step can assemble.
#
# Pull requests no longer write into CHANGELOG.md's [Unreleased] section (every
# pair of PRs in flight conflicted there); each adds changelog.d/<slug>.md, and
# scripts/changelog-assemble.sh folds them into the release section when a
# version is cut. A fragment with a heading the assembler does not know, or a
# bullet before any heading, would otherwise be found by whoever cuts the next
# release, long after the PR that wrote it merged. This runs the assembler's own
# parser, so the guard and the release step cannot disagree about the format.
#
# A PR is not required to add a fragment: internal refactors and CI changes
# have nothing to tell an operator.
#
# Usage: check-changelog-fragments.sh
#   CHANGELOG_ROOT overrides the tree that is checked (used by the .test.sh).
set -euo pipefail
exec bash "$(dirname "${BASH_SOURCE[0]}")/changelog-assemble.sh" --check
