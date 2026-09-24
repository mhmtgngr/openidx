# Architecture and product decision records

An ADR is a one-page record of a decision that changes the product's scope,
priorities, defaults, architecture or data model. The human maintainer approves
every ADR. AI agents may draft one, but they do not decide (see the
[AI working agreement](../AI-WORKING-AGREEMENT.md)).

## How to write one

Copy the template below into `docs/adr/<NNNN>-<short-title>.md`, using the next free
number. Keep it to one page. An ADR is never edited after it is accepted. To
change a decision, write a new ADR that supersedes the old one, and set the old
one's status to "Superseded by NNNN".

```markdown
# NNNN — Title

- **Status:** Proposed | Accepted | Superseded by NNNN
- **Date:** YYYY-MM-DD
- **Approved by:** @handle (the human who took the decision)

## Context
What forces the decision; the facts, with links.

## Options
1. …
2. …

## Decision
What we will do, in one or two sentences.

## Consequences
What becomes easier, what becomes harder, and what we now will not do.
```

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-product-focus-and-trusted-core.md) | Product focus, the Trusted Core milestone, and freezing the global-scale programme | Accepted |
