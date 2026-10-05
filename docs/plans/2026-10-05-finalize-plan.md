# Finalize plan: from v1.39.0 to v2.0 LTS

*Written 2026-10-05 against `main` at `df43b39`, by an AI session, for the
maintainer (@mhmtgngr) to decide on. Re-checked the same day at 12:30 UTC
against `5380aa8`, after the maintainer merged the open pull requests; §9 holds
the re-check log and every figure below is the re-checked one. Nothing here
changes a priority until the maintainer confirms it; the proposed ROADMAP edits
are in §7.*

The maintainer has asked several sessions to "finish the project" and it has
not finished. This document says why, defines what finished means in a way
that can be checked, records what was verified today, and lays out the work in
the order that closes the gap fastest. It is meant to be the one file a new
session reads first.

## Özet (TR)

- **Neden bitmiyor:** "Bitti" tanımı M1'in 16 çıkış kriteri; 5'i kapandı, 11'i
  açık. Açıkların üçü yalnızca proje sahibinin yapabileceği işler (pentest
  bütçesi, mağaza hesapları, GitHub ayarları). Bu arada 4-5 Ekim'de 36 saatte
  57 PR birleşti, 45'i M3 kapsamındaki tedarikçi erişimi özellikleri; ADR 0002
  hâlâ "onay bekliyor". Hedef çizgisi her oturumda ileri kayıyor.
- **Şu an (12:30 UTC):** Açık PR kalmadı; 6 PR, bağımlılık düzeltmesi (#1089)
  ve Tailwind 4 geçişi (#1090) aynı gün birleşti ve Security Scanning yeşile
  döndü. Documentation iş akışı hâlâ her push'ta kırmızı (GitHub Pages
  açılmadı). v1.39.0'dan bu yana 65 değişiklik yayımlanmadı; 547 uzak dal var.
- **Plan:** A) bu hafta kanamayı durdur (CI yeşil, v1.40.0 kes, 2 bug);
  B) tek oturumda sahibin kararları ve 5 depo ayarı; C) 8 haftada 11 açık M1
  maddesini sırayla kapat; D) v2.0 LTS. Özellik dondurma kuralı §5'te.

## 1. Why "finish" keeps not happening

Each cause below is a fact about the repository or GitHub on 2026-10-05, not
an opinion about effort.

1. **"Finished" is defined, but 11 of its 16 parts are open.** ROADMAP.md
   defines done as M1 exiting with every criterion closed with evidence
   ([#954](https://github.com/mhmtgngr/openidx/issues/954), target
   mid-December 2026). GitHub's sub-issue summary on #954 reads 5 of 16
   complete. Closed: #955, #956, #957, #961, #963. Open: #958, #959, #960,
   #962, #964, #965, #966, #967, #968, #977, #980.

2. **Three of the open parts cannot be done by an AI session at all.** They
   need money, accounts or repository-admin rights: the penetration test and
   its budget (#959), the mobile app ID, signing keys and store accounts
   (#966), and the repository settings in #978 (private vulnerability
   reporting, GitHub Pages, Discussions, branch protection, Renovate). #978
   has been open since 2026-09-23 with every box unchecked, and the
   `Documentation` workflow has failed on every push to `main` since then
   because Pages is not enabled. A session told to "finish" reaches one of
   these walls and does something else instead.

3. **New features kept landing during a milestone whose rule is "no new
   features".** `git log --first-parent` shows 57 merges between 2026-10-04
   12:41 UTC and 2026-10-05 12:22 UTC, 45 of them from `claude/phase2-*`
   branches: vendor (third-party) access,
   which is M3 ([#975](https://github.com/mhmtgngr/openidx/issues/975)) and
   which ROADMAP.md says starts after M1's security items. The `[Unreleased]`
   changelog has 14 `Added` entries, all vendor access.
   [ADR 0002](../adr/0002-third-party-access-and-temporary-privilege.md),
   which proposes that work, still reads *Status: Proposed, Approved by:
   pending*. The AI working agreement §1 says work outside the current
   milestone needs the maintainer's go-ahead; in practice the agent decided.
   Every feature adds surface that M1 must then verify (two-sided tests, an
   evidence row, pentest scope), so the finish line moves with each one.

4. **Release hygiene is not kept, so a release is not possible today.**
   `docs/RELEASING.md` requires a green `main` first. This morning the
   `Security Scanning` workflow was red on every push to `main` (dependency
   CVEs in the console's lockfile); #1089 and #1090 fixed that by 07:09 UTC.
   `Documentation` is still red on every push (Pages, §3.2). 65 changelog
   entries sit under `[Unreleased]` since v1.39.0 on 2026-09-28, the exact
   failure mode RELEASING.md warns about. There are 547 remote branches (464
   when #967 was written). Two bugs are open and unowned
   ([#1013](https://github.com/mhmtgngr/openidx/issues/1013),
   [#1004](https://github.com/mhmtgngr/openidx/issues/1004)).

5. **Nothing persistent tells a new session what is left.** `CLAUDE.md` is
   git-ignored, so a cloud session does not load the working agreement
   (decision pending in #978). ROADMAP.md was last updated 2026-09-24 and does
   not show which M1 criteria have closed. Each session rediscovers the state
   and picks its own next task. This file exists to end that.

## 2. What "finished" means

v2.0 LTS is finished when every line below is true and can be pointed at.
Anything not on this list is not finishing; it is a new feature and goes to
the M3 or "Later" backlog.

- [ ] All 16 sub-issues of #954 are closed, each with its evidence linked, and
  #954 is closed.
- [ ] Every workflow is green on the commit that gets the `v2.0.0` tag.
- [ ] The release is cut per `docs/RELEASING.md`: changelog section renamed,
  `VERSION` synced, lite install pinned, signed binaries and chart, images
  retagged, the display = enforcement report attached, mobile artifacts
  attached.
- [ ] The post-release verification job from #960 is green for that tag.
- [ ] The three operator-run rows in `docs/evidence/release-gate.md` and the
  DR drill row for #962 each have one dated entry.
- [ ] The README maturity matrix is re-checked: every "GA candidate" is
  promoted to GA or kept at Beta with the missing evidence named.
- [ ] ROADMAP.md marks M1 done and names the M2 start.

## 3. State on 2026-10-05

### 3.1 Local checks on `main` at `df43b39`

These are the checks the AI working agreement §3 names. All ran in a fresh
cloud container. The same checks were re-run on `5380aa8`; §9 has that row.

| Check | Result |
|---|---|
| `go build ./...` | exit 0 |
| `go vet ./...` | exit 0 |
| `go test -short ./...` | exit 0: 112 packages ok, 0 failed, 20 with no test files |
| Console `npm run type-check` | exit 0 |
| Console `npm run lint` | exit 0 |
| Console `npx vitest run` | 1393 of 1394 tests pass. The one failure, in `src/pages/organizations.test.tsx`, passes when the file runs alone (6 of 6), so it is a timing flake under full-suite load, not a product defect. It belongs in C3 as a test to make robust. |
| Console `npm run build` | exit 0 (built; the usual chunk-size warning) |
| `make guards` | 75 of 78 pass. The 3 failures are environment-only: `check-chart-images.sh` and its self-test need `helm`, which the container lacks, and `check-third-party-notices.sh` ran a `go-licenses` built with Go 1.24.7 against the 1.26.8 toolchain. CI's `License Compliance` job passes on the same commit. |

### 3.2 CI on `main`

Latest completed run per workflow on `main` (the `df43b39` push, or `a2fdc98`
where `df43b39` was still running).

| Workflow | State | Cause |
|---|---|---|
| Go CI, Frontend CI, Docker Build, CodeQL, SAML interop, Scorecard | green | |
| OIDC conformance (nightly) | green on 2026-10-02, 10-03, 10-04 | |
| Display = enforcement | green on v1.37.0, v1.38.0, v1.39.0 | runs on release only, as designed |
| Security Scanning | green since #1089 merged at 07:09 UTC; green on `5380aa8` | It was red on every push until then: `Go Dependency Scan` and `NPM Dependency Scan` failed at the Trivy gate on `web/admin-console/package-lock.json` (`axios` 1.19.0, `brace-expansion` 5.0.9). #1089 bumped `axios` to 1.20.0, `brace-expansion` to 5.0.12 and `dompurify` to 3.4.16 and replaced the bare `npm audit` gate with `scripts/check-npm-audit.sh`, which allows an advisory only with a reason and an expiry in `web/admin-console/.npm-audit-ignore`. #1090 moved the console to Tailwind 4, which removed the dev-only `braces` chain, so that file has no entries. |
| **Documentation** | **red on every push, still red on `5380aa8`** | The `deploy` job fails at `Deploy to GitHub Pages`: Pages is not enabled (#978, admin only). |

Five consecutive merges on 2026-10-04 21:45 cancelled each other's Go CI,
Docker and CodeQL runs; only the last merge in a burst gets a verdict.

### 3.3 Open work

| What | Count | Detail |
|---|---|---|
| Open M1 sub-issues | 11 | §3.4 |
| Open pull requests | 0 | #1081 to #1087, the seven authorization-path PRs, were merged by the maintainer between 05:25 and 08:12 UTC, with #1089 (dependency bumps), #1090 (Tailwind 4), #1091 (changelog) and #1092 (doc redaction). |
| Unreleased changelog entries | 65 | 14 Added (vendor access), the rest Fixed and Security. Last release v1.39.0 on 2026-09-28. |
| Open bugs outside the roadmap | 2 | #1013 (three OIDC conformance warnings waived, not fixed), #1004 (the full Compose stack's Alertmanager never starts). |
| Maintainer decisions pending | 7 in ROADMAP.md, 8 in #978 | Since 2026-09-23. |
| Remote branches | 547 | #967 asks for the merged ones to be deleted. |
| ADR 0002 | Proposed, approval pending | Its Phase 1 and Phase 2 are merged. |

### 3.4 The 11 open M1 criteria: done, remaining, owner

"Verified" means a grep or a workflow run on `main` today; "per issue" means
the issue's own list, not re-checked here.

| Issue | Verified done on `main` | Remaining | Who |
|---|---|---|---|
| [#958](https://github.com/mhmtgngr/openidx/issues/958) OIDC conformance in CI | The nightly workflow exists and is green three nights running. | Fix the three warnings in #1013 instead of waiving them; state in `docs/OAUTH-OIDC.md` which profiles pass; decide on paid certification. | AI, then owner decision |
| [#959](https://github.com/mhmtgngr/openidx/issues/959) Pentest and baseline | Scorecard runs in CI and its badge is in the README. 40 high CodeQL alerts triaged in `docs/evidence/codeql-triage.md`. | Vendor, scope and budget; remediation; ASVS L2 self-assessment committed; the remaining CodeQL alerts triaged. | **Owner** for the test; AI for ASVS and triage |
| [#960](https://github.com/mhmtgngr/openidx/issues/960) Release integrity | All 14 Go Dockerfiles use `TARGETARCH`; none hard-codes amd64. The chart and `SHA256SUMS` are cosign-signed. | Helm image tags still default to `latest` (3 places); `values-prod.yaml` still pins `v0.1.0` nine times; images are not cosign-signed (`docker.yml` has no cosign step); 17 action references are SHA-pinned against 211 by tag; `trivy-action@master` is still used in `docker.yml` and `security-scan.yml`; no post-release verification job. | AI |
| [#962](https://github.com/mhmtgngr/openidx/issues/962) Operational evidence | Nothing verifiable: `ci.yml` has no restore or upgrade job; no alert rule carries `runbook_url`; no SLO is defined; the operator rows in `docs/evidence/release-gate.md` are empty. | Restore job, upgrade job, one alert set with runbook links, three to five SLOs; one recorded DR drill. | AI for CI and docs; **owner** for the drill |
| [#964](https://github.com/mhmtgngr/openidx/issues/964) Backend robustness | A dead-code gate runs in `ci.yml`. | The `app.bypass_rls` setting is still in `internal/common/database/rls.go`; no production code refuses a superuser or BYPASSRLS connection (only a test mentions them); the migrator has no advisory lock; `ci.yml` still selects database tests by `-run` name pattern in at least six places. | AI; **owner review** before merge |
| [#965](https://github.com/mhmtgngr/openidx/issues/965) Console session security | `nginx.conf` sends a Content-Security-Policy. `internal/oauth/browser_session.go` sets an HttpOnly browser-session cookie. | `web/admin-console/src/lib/auth.tsx` still reads and writes `localStorage` (19 references); the refresh token is not yet a cookie; no CSRF or script-cannot-read test; no WebSocket tickets; `login.tsx` is not on the shared client. | AI; **owner review** before merge |
| [#966](https://github.com/mhmtgngr/openidx/issues/966) Mobile client | `FLUTTER_VERSION` is defined in the build workflow. | The app ID is still `com.example.openidx_client`; `FLUTTER_VERSION` is defined and not used; release signing, per-ABI builds, artifact names, freezing `agent-android/`. | **Owner** for ID, signing, accounts; AI for the rest |
| [#967](https://github.com/mhmtgngr/openidx/issues/967) Supply chain and CI hygiene | | CI runs Node 20 in six places and `package.json` has no `engines`; the gitleaks allowlist still matches real API keys; `docker.yml` has no path filter; Renovate is not installed; 543 branches. | AI; **owner** for Renovate and branch deletion |
| [#968](https://github.com/mhmtgngr/openidx/issues/968) Release policy | Nothing: `SECURITY.md` still supports "Latest 1.x". | Cadence, LTS window, semver scope, changelog fragments, upgrade guide. | **Owner decides**; AI writes |
| [#977](https://github.com/mhmtgngr/openidx/issues/977) Site config out of the tree | Per issue: the product defaults no longer name the site. | Per issue: the production compose overlay, nginx site config, BrowZer cert paths, site-only scripts, live-site e2e specs, the Helm console port bug. Needs the live environment changed in the same step. | AI prepares; **owner** applies on the live site |
| [#980](https://github.com/mhmtgngr/openidx/issues/980) OPA deployable | The policy's braces balance (27/27); `opa check` runs in `ci.yml`; `OPA_URL` is set on four Compose services. | Helm `policyConfigMap` is still `""` so Helm OPA has no policy; `internal/common/middleware/opa.go` has no observe mode; rules for API keys, internal tokens and delegations; the loaded-policy startup probe; e2e with OPA on. #1082 and #1084, merged 2026-10-05, added the access-review and governance rules. | AI |

## 4. The plan

Each line is one pull request unless it says otherwise. A pull request names
the issue it advances in its first line and states what was and was not
verified (working agreement §3.5).

### Phase A: stop the bleeding (week of 2026-10-06)

| # | Work | Who | Closes or unblocks |
|---|---|---|---|
| A1 | **Done 2026-10-05** by #1089 (the three bumps and the reasoned-exception audit gate) and #1090 (Tailwind 4, which removed the unfixable dev-only chain). `Security Scanning` has been green on every push since. | AI | `main` green |
| A2 | Enable GitHub Pages (Settings → Pages → Source: GitHub Actions). Also, in the same sitting: private vulnerability reporting, Discussions, protect `main` (require `Required Checks` and a code-owner review), install Renovate. | **Owner**, about 20 minutes | `Documentation` green; #978; starts #967 |
| A3 | Fix #1013 (the three conformance warnings) and #1004 (Alertmanager placeholders). Two PRs. | AI | #958 progress; the full stack starts |
| A4 | **Done 2026-10-05.** All six (#1082 to #1087) merged by 08:12 UTC; no pull request is open. | **Owner** | Queue cleared; #1082 and #1084 advance #980 |
| A5 | Cut **v1.40.0** per `docs/RELEASING.md`: rename `[Unreleased]`, sync `VERSION` and the ten held versions (`scripts/check-version-sync.sh --enforce`), pin the lite install, then dispatch `release.yml`. A1 is done; only A2 (Pages) still keeps the tagged commit from being all green. | AI prepares the PR; **owner** dispatches | 65 entries shipped; one more display = enforcement report on record |

### Phase B: decide, in one sitting (by 2026-10-10)

These are the maintainer's, by the working agreement §1. Each gets written
down in ROADMAP.md or an ADR; a recommendation is offered for each, with the
reason.

| # | Decision | Recommendation | Why |
|---|---|---|---|
| B1 | ADR 0002 (third-party access): approve, or send back? | **Approve what is merged (Phases 1 and 2) and freeze Phase 3 onwards until M1 exits.** Record it in the ADR's header. | The code is on `main` and in the changelog; pretending otherwise helps nobody. Freezing the rest stops the finish line moving. |
| B2 | Feature freeze until #954 closes | **Yes.** The rule is in §5. | Cause 3 in §1. |
| B3 | Track `CLAUDE.md` with the single line `@docs/AI-WORKING-AGREEMENT.md` | **Yes.** Move private notes to `~/.claude/CLAUDE.md`. | Every cloud session then loads the agreement. Cause 5 in §1. |
| B4 | Project goal: internal product, community project, or company | No recommendation; this is yours. It decides whether M2's design-partner programme is the next milestone or not. | |
| B5 | Release cadence: monthly minor, v2.0 as the first LTS with 12 months of security fixes | **Yes.** | #968's proposal; matches the one real deployment's pace. |
| B6 | Pentest: vendor, scope and budget, or ship v2.0 with #959 open and say so | **Choose the vendor now.** Lead times run weeks. If it cannot land by December, v2.0 ships with the pentest named as the one open criterion in the README, not hidden. | #959 is the longest external dependency. |
| B7 | Mobile: final app ID and bundle ID | Pick a reverse-DNS ID you own; the server's QR provisioning expects `com.openidx.agent` for the Kotlin app, so the Flutter app needs a different, final name. | #966 cannot start without it. |
| B8 | The rest of ROADMAP.md's open decisions: reference customer, documentation language, contact domain, DCO for AI commits | English first with Turkish translation; GitHub-only contact; keep the agent's sign-off and require your review on security paths, which is already the rule. | Each is a one-line answer; the project has waited two weeks on them. |

### Phase C: close M1, in this order (2026-10-13 to 2026-12-05)

Ordered by how much an AI session can do unaided, so the owner-dependent
items start early and run in parallel with the rest. Items marked **review**
touch the working agreement §2 paths and wait for the maintainer before merge.

| Order | Issue | Pull requests | Owner's part |
|---|---|---|---|
| C1 | #958 | (1) #1013's three warnings fixed with tests; (2) `docs/OAUTH-OIDC.md` states the passing profiles and the waivers. Then close. | Decide on paid certification (a line in the issue). |
| C2 | #960 | (1) Helm image tags default to `.Chart.AppVersion`, drop the `v0.1.0` pins, fix the console `containerPort` from #977; (2) cosign-sign images in `docker.yml` and document verification; (3) pin all actions by SHA and replace `trivy-action@master`; (4) derive the retag list from the build matrix and build a tag's images from the tag; (5) post-release verification job. Then close. | None. |
| C3 | #967 | (1) Node 22 in CI plus `engines`; (2) gitleaks allowlist narrowed to the fixture plus a planted-key test; (3) path filters on `docker.yml` and CodeQL, drop the duplicate race and `ci-web` jobs; (4) site-specific jobs moved to a nightly workflow; (5) Go 1.27 as its own change. Then close. | Renovate installed (A2); delete the merged branches once the AI lists them. |
| C4 | #980 | (1) Ship the policy in the chart as the `policyConfigMap` default and probe a known decision at startup; (2) rules for API keys, internal service tokens and delegated permissions, two-sided tests; (3) observe mode logging `would deny`; (4) e2e for admin and end-user journeys with `ENABLE_OPA_AUTHZ=true` on Compose and Helm. Then close, and #956's last item (OPA on for fresh installs) lands. | None. |
| C5 | #964 **review** | (1) Run every database-gated package whole in the DB job; (2) refuse to start in production on a superuser or BYPASSRLS connection, with a test; (3) replace the settable bypass with a dedicated BYPASSRLS role and pool, with the GUC test; (4) migrator: advisory lock, re-read after lock, apply and record in one transaction, multi-statement SQL, non-transactional migrations, with concurrency tests. Then close. | Review each. |
| C6 | #965 **review** | (1) Refresh token as an `HttpOnly; Secure; SameSite=Strict` cookie with CSRF, two-sided tests; (2) access token in memory only, WebSocket and terminal tickets; (3) `login.tsx` on the shared client, localhost fallback removed, the two related bugs; (4) CSP enforced and the e2e suite clean of violations. Then close. | Review each. |
| C7 | #962 | (1) Backup, wipe, restore and verify as a CI job; (2) install the previous release, seed, upgrade to HEAD and verify as a CI job; (3) one alert rule set with `runbook_url` on every rule, and the data-loss target made to agree with the backup cadence; (4) three to five SLOs with dashboards. | Run one DR drill on the live install and fill the row in `docs/evidence/release-gate.md`; fill the darkprobe and assignment-report rows while there. |
| C8 | #968 | (1) Release policy: cadence, LTS window, semver scope, `SECURITY.md` supported-versions table, `docs/RELEASING.md`; (2) changelog fragments with the current `CHANGELOG.md` archived. After B5. | Decide B5. |
| C9 | #977 | (1) Production compose overlay and `.env.production` as required variables, tests updated; (2) nginx site template and BrowZer certificate paths made generic; (3) site-only scripts and live-site e2e specs moved out. Each needs the live environment changed at the same time. | Set the new variables on the live site as each PR merges. |
| C10 | #959 | (1) OWASP ASVS L2 self-assessment committed; (2) every remaining CodeQL alert fixed or dismissed with a reason; (3+) remediation PRs as findings arrive. | Vendor engaged (B6); report received; public summary approved. |
| C11 | #966 | (1) The app ID changed, Flutter version pinned, per-ABI release builds, artifacts named after the app they contain; (2) `agent-android/` and the desktop shell frozen: Experimental in the matrix, their empty test jobs removed; (3) iOS certificate pinning and biometric unlock ported. | App ID (B7), upload keystore with Play App Signing, Apple distribution signing, internal-testing and TestFlight uploads. |

### Phase D: v2.0 LTS (week of 2026-12-08)

1. Every item in §2 checked, in that order.
2. The release cut per `docs/RELEASING.md`, by dispatch if the tag push is
   refused.
3. The README maturity matrix updated in the same PR as the release notes:
   GA candidates promoted where the M1 evidence now exists.
4. ROADMAP.md: M1 done, M2 open, "Last updated" set.

The mid-December target in #954 holds only if Phase A finishes this week, B
happens in one sitting, and the §5 freeze is kept. The pentest is the one
item whose timing is outside the repository; B6 decides what happens if it is
late.

## 5. Rules until v2.0 ships

1. **No new features on `main` until #954 closes.** A feature is anything
   that adds an endpoint, a table, a console page, a request type or a
   client capability that no open M1 issue asks for. A feature idea becomes
   an issue labelled `M3` or `later` and stops there.
2. **Every pull request names the M1 issue it advances in its first line.**
   A pull request that cannot name one is either a bug fix (say which bug)
   or out of scope.
3. **A red workflow on `main` is the first task of the next session**, before
   anything else, and a release is never cut on a red commit.
4. **At most three stacked pull requests at a time.** Forty-five merges in one
   day cancelled five CI runs in a row and left nothing verified but the last.
5. **A session that reaches an owner-only item stops and writes the exact ask
   into the issue**, instead of picking a different task. The owner's queue is
   §4 Phase B and the "Owner's part" column.
6. **One topic per pull request; a changelog entry is one or two user-facing
   lines** (working agreement §4).

## 6. How to run an AI session against this plan

Start every session with the same instruction, so the plan, not the session,
chooses the work:

```text
Read docs/plans/2026-10-05-finalize-plan.md, ROADMAP.md and
docs/AI-WORKING-AGREEMENT.md. Check that main is green; if not, fix that first.
Then take the first unfinished line of Phase C (or Phase A while it is open)
whose owner part is done, and do exactly that one pull request. Do not start
a feature. If the next line needs me, write the exact ask into its issue and
stop.
```

When a line in §4 is done, the pull request that does it also ticks it in
this file, so the next session sees the current state without rediscovering
it.

## 7. Proposed edits to ROADMAP.md (for the maintainer to apply)

ROADMAP.md is the maintainer's; these are the edits this analysis suggests.

1. In the M1 table, add a **Status** column: *closed* for #955, #956, #957,
   #961, #963; *open* for the rest, with a one-line "remaining" taken from
   §3.4.
2. In M0, tick the "review and merge the branch" item (merged) and leave the
   repository-settings item open until A2 is done.
3. Under M3, note that ADR 0002 Phases 1 and 2 are merged and that the rest is
   frozen until M1 exits (B1).
4. Add §5's feature-freeze rule under "Milestones" in one sentence, and link
   this plan.
5. Resolve the seven open decisions per Phase B, or record the ones that
   stay open with a date.
6. Set "Last updated" to the date of the edit.

## 8. What this plan does not cover

- The M2 design-partner programme and the M3 wedge work. They start after
  #954 closes, as ROADMAP.md already says.
- Anything in the "Later" and "On hold" lists.
- Re-running the live-site controls in `docs/evidence/operational.md`. They
  need the maintainer's deployment and are owner work in C7.

## 9. Re-check log

One row per re-check. A re-check re-reads GitHub and re-runs the §3.1 checks;
it changes the figures above in place and records here what moved.

| When (UTC) | `main` | What moved | Local checks |
|---|---|---|---|
| 2026-10-05 12:30 | `5380aa8` | 12 merges since `df43b39`: #1081 to #1087 (authorization paths), #1089 (dependency bumps and the npm audit gate), #1090 (Tailwind 4), #1091 (changelog), #1092 (doc redaction). Open PRs 6 → 0. Security Scanning red → green. Documentation still red. Unreleased entries 58 → 65. Remote branches 543 → 547. M1 sub-issues still 5 of 16 closed. Phase A: A1 and A4 done; A2, A3, A5 open. | On the merged tree, all green: `go build` and `go vet` exit 0; `go test -short` 112 packages ok, 0 failed; console `type-check` exit 0, `lint` 0 errors (188 warnings, the standing baseline), `vitest` 1395 of 1395 (the `organizations.test.tsx` flake from the morning did not recur), `build` exit 0, `npm audit --audit-level=high` exit 0 with only lower-severity dev-tooling advisories left. |
