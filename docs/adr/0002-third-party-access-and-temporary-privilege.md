# 0002 — Third-party access as a sponsored, expiring identity, and one framework for temporary privilege

- **Status:** Proposed
- **Date:** 2026-09-28
- **Approved by:** _pending_ — @mhmtgngr decides. Drafted by an AI agent from
  [docs/plans/2026-09-28-ucuncu-taraf-erisimi-ve-gecici-yetkilendirme-cercevesi.md](../plans/2026-09-28-ucuncu-taraf-erisimi-ve-gecici-yetkilendirme-cercevesi.md)
  (in Turkish), which holds the full design, the threat model and the phased
  plan. Nothing here is decided until the maintainer confirms it in writing.

## Context

The entry wedge in [ADR 0001](0001-product-focus-and-trusted-core.md) is
privileged and third-party access without a VPN, approved and recorded. Today:

- The only feature built for outside support staff is the temporary access
  link. After V0 it runs through the PAM launch core, but it is still an
  anonymous URL: no identity, no MFA, and its audit events are log lines
  (`internal/access/temp_access.go`).
- `users` has no identity type, sponsor or account expiry. Nothing stops an
  outside user from holding `operator` or `admin`, and nothing ends their
  account when the engagement or their sponsor ends.
- Temporary privilege exists in five request types (role, group, application,
  network service, vault credential) with one expiry sweep
  (`internal/jitgrant/jitgrant.go`, `internal/governance/jit_expiry.go`), but
  PAM entry approvals run in a second engine with admin-only approvers and a
  fixed one-hour window, and SSH certificates and cloud JIT have no approval
  and no per-target check.
- The kill switch, deprovisioning and the lifecycle sweep do not touch
  `pam_entry_grants`, temp links or brokered SSH/cloud sessions
  (`internal/access/kill_switch.go`).
- Approval policies store `MinApprovals`, step order and `max_wait_hours` and
  enforce none of them.

Issue [#975](https://github.com/mhmtgngr/openidx/issues/975) (M3) asks for
vendor identities with a sponsor and an expiry, clientless access, approved
time-boxed requests, recorded sessions the sponsor can watch, and reliable
ending. Issue [#970](https://github.com/mhmtgngr/openidx/issues/970) says M3
starts after M1's security items merge.

## Options

1. **Keep the temporary link as the third-party path** and harden it further
   (IP rules, shorter windows). Cheapest; keeps an anonymous, unattributable
   path that no identity control can reach.
2. **A separate tenant per vendor.** Reuses tenancy; contradicts it, because
   the vendor needs the host organization's targets and RLS forbids exactly
   that reach.
3. **The outside user is a real identity in the host organization**, typed
   `external`, bound to a vendor organization record, with a mandatory
   sponsor and expiry, a role cap of `user`, MFA before any grant activates,
   PAM controls (approval, recording, overlay) forced in code, no credential
   reveal, and every grant ending with the account, the sponsor or the vendor.
   Temporary privilege for internal users runs on the same spine: eligibility
   is standing, privilege is requested, approved, time-boxed and swept, and
   PAM entry, SSH principal and cloud role become request types in the one
   governance engine.

## Decision (proposed)

Option 3, in the phases the plan document lays out: Phase 0 fixes the
controls that already claim to work (kill-switch scope, temp-link audit,
inert approval-policy fields, ungated Guacamole route connect, SSH CA and
cloud JIT checks) and fits M1; Phases 1–3 deliver #975 after M1; Phase 4
deepens internal JIT; Phase 5 is #976. The twelve individual decisions
(D1–D12 in the plan's §12: identity representation, the temp link's fate,
merging the two approval engines, the external MFA policy, sponsor departure,
duration ceilings, session hardening defaults, vendor IdP federation,
break-glass, naming, admin bypass, and where Phase 0 is tracked) each carry a
recommendation and wait for the maintainer.

## Consequences

- **Easier:** one approval queue, one notification set and one evidence row
  per grant type; a vendor's access is a query, not an investigation; the
  entry wedge has the product shape the roadmap describes.
- **Harder:** the PAM entry request flow changes shape, so existing installs
  need a compatibility release; a dozen new negative tests and evidence rows
  are the definition of done; BrowZer remains OpenZiti's component and is not
  proven end-to-end in CI until Phase 3 adds a smoke test.
- **We will not:** give outside users a VPN or a network segment, a shared
  account, a password, or a console role above `user`; keep an anonymous link
  as the durable path once V1 ships; or show any switch or field the code
  does not enforce.
