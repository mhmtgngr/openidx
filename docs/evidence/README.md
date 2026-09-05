# Control evidence

DoD item 7 is *"the §5 controls have run at least once on cadence, with
evidence."* A checklist nobody can point at is not evidence, so this is where
the pointing happens.

Controls split two ways, and the split is the whole point:

| | Who runs it | What "evidence" is |
|---|---|---|
| **Automated** ([release-gate.md](release-gate.md)) | CI, on every push | the run link — the control ran or the merge was blocked |
| **Operator-run** ([operational.md](operational.md), [display-equals-enforcement.md](display-equals-enforcement.md)) | a person, against a live deployment | a dated row in the file, with the output |

**Nothing in this directory is pre-filled.** An automated control's evidence
is the CI run that just passed on the commit you are releasing; an
operator-run control has no evidence until someone runs it and writes the
date down. A row with no date has not been done — that is the honest state,
and reading it that way is the point of keeping the file.

## Filing an operator-run control

1. Run it on the deployment (not on a laptop, not on the CI stack).
2. Add a row: the date, who ran it, the outcome, and where the output lives
   (a paste, a ticket, a screenshot path — anything a reader can go and see).
3. Commit it. A control's evidence living only in someone's terminal history
   is the same as no evidence.

## Filing a release

At tag time, copy the CI run URL for the release commit into
[release-gate.md](release-gate.md)'s log. That single link covers every
automated control in one go, because they all ran on that commit — which is
the reason for automating them.
