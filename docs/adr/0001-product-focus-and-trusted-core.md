# 0001 — Product focus, the Trusted Core milestone, and freezing the global-scale programme

- **Status:** Accepted
- **Date:** 2026-09-23
- **Approved by:** @mhmtgngr. The maintainer instructed that the
  recommendations of the 2026-09-23 project analysis be applied and planned.

## Context

The analysis of v1.36.0 is in
[docs/plans/2026-09-23-proje-analizi-ve-yol-haritasi.md](../plans/2026-09-23-proje-analizi-ve-yol-haritasi.md),
which is in Turkish. It found the following:

- **The platform is broad and well engineered.** It covers IAM, IGA, PAM and
  ZTNA. It has one real deployment, no external users, and one maintainer.
- **Advertised controls did not always enforce.** Several controls were
  advertised but not enforced until September 2026: PKCE at the live
  authorize endpoint, scope restriction, introspection ownership, and
  back-channel logout.
- **Enforcement is off by default.** Assignment enforcement, ABAC and OPA
  authorization all ship off.
- **Nothing is externally verified.** Nothing has run a conformance suite or
  had a penetration test.
- **Planned scale is far ahead of demand.** A 36-week global-scale
  (cell-architecture) programme targets 50 million users, while the one real
  deployment runs on a single VM.
- **Priorities are not defined.** No target customer, wedge or single roadmap
  is written down, and product decisions had been delegated to AI agents.

## Options

1. Keep adding features across all four pillars, and continue the
   global-scale programme.
2. Focus on one entry wedge and first harden and verify what already exists.
   Defer scale work until a customer needs it.

## Decision

Option 2:

- **Target customer:** organizations of 200–5,000 people that must keep their
  data in their own infrastructure. Examples are those under KVKK, BDDK or
  public-sector security rules, in healthcare or education, or
  foundations/NGOs. The MSPs and integrators who serve them are also in scope.
- **Entry wedge:** privileged and third-party access without a VPN, approved
  and recorded, with SSO and MFA included (PAM + ZTNA + SSO).
- **North Star metric:** the number of independent organizations running
  OpenIDX in production. The first goal is three design partners within 90
  days.
- **Next milestone:** M1 "Trusted Core", which becomes v2.0 LTS. It adds no
  new features; it covers hardening, secure defaults, conformance and interop
  tests, an independent penetration test, a lite install, release integrity
  and an honest maturity matrix.
- **Frozen:** the global-scale / cell-architecture programme. The trigger to
  restart it is the first customer or MSP that needs more than one region.
- **Who decides:** product decisions are taken by the human maintainer and
  recorded as ADRs. AI agents propose options; they do not decide
  ([AI working agreement](../AI-WORKING-AGREEMENT.md)).

## Consequences

- **The roadmap is simpler.** [ROADMAP.md](../../ROADMAP.md) is the only source
  of priorities, and the work items are GitHub issues.
- **Some work waits.** New pillars, new clients and scale work wait until M1
  exits. The cell design documents stay in the repository as reference.
- **Wedge features come after M1.** Vendor-access V1 and the SSH command
  policy start once M1's hardening is under way. Security fixes to the
  console and the mobile client are part of M1.
