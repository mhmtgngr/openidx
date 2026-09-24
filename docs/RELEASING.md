# Releasing OpenIDX

OpenIDX follows [Semantic Versioning](https://semver.org): `vMAJOR.MINOR.PATCH`.
A release is cut by pushing a `vX.Y.Z` git tag — everything else is automated.

## Pre-flight

1. `main` is green (Go CI, Frontend CI, Docker Build, Helm, Terraform).
2. All PRs intended for the release are merged.
3. Update `CHANGELOG.md`: rename the `[Unreleased]` section to
   `[X.Y.Z] - YYYY-MM-DD`, add its compare-link definition at the bottom of the
   file, and start a fresh empty `[Unreleased]`.

   **This is the step that gets skipped.** It was missed on all eight releases
   from v1.28.0 to v1.33.3, so 359 lines of shipped work sat under
   `[Unreleased]` reading as unshipped, and the compare links stopped at
   v1.17.0. If you do only one thing here, do this one.
4. `VERSION` matches the tag you are about to push, and
   `bash scripts/check-version-sync.sh --enforce` is green — it holds the
   console, the Helm chart's `appVersion`, the Flutter client and the seven
   OpenAPI specs under `api/openapi/` to that number.

## Cut the release

```bash
git checkout main && git pull
git tag -a vX.Y.Z -m "OpenIDX vX.Y.Z"
git push origin vX.Y.Z
```

### …or without pushing a tag

Some environments cannot push a tag at all: a branch-scoped git credential
answers `HTTP 403` for `refs/tags/*`, and that is the session's write scope
rather than a fault to route around. (The error can arrive disguised — over
HTTP/2 it surfaces as `send-pack: unexpected disconnect while reading sideband
packet`. Re-run with `git -c http.version=HTTP/1.1` to see the 403 itself.)

For those, run **Actions → Release → Run workflow** with the version, or:

```bash
gh workflow run release.yml --ref main -f version=vX.Y.Z
```

`release.yml` creates the tag at the chosen commit and then does everything the
tag push would have. **It is not a lesser path**: because a tag created under
`GITHUB_TOKEN` starts no workflow, `release.yml` explicitly hands off to
`docker.yml` so the images still get their `X.Y.Z` / `X.Y` / `X` / `stable`
tags. Without that hand-off a dispatched release would publish binaries and a
chart over images that only ever carried a `:sha` tag — a release whose version
tags do not exist. `scripts/check-release-dispatch.sh` holds the two paths
together in CI, and its `.test.sh` proves it goes red on that exact regression.

The parity is *by name*, not just by job. On a pushed tag `docker/metadata-action`
already publishes the un-prefixed `X.Y.Z` / `X.Y` / `X` through `type=semver`;
that matches a tag ref and nothing else, so on the dispatch path nobody would
create them and `docker pull …:1.34.0` would 404 after an apparently complete
release. The retag job therefore stamps both spellings on both paths — on the
tagged path the un-prefixed three are re-pointed at the digest they already
name, which `imagetools create` does idempotently.

The mobile artifacts have the same asymmetry and the same answer.
`client-mobile-release.yml` attaches the APK and the IPA on a pushed tag; a
token-created tag starts it no more than it starts `docker.yml`. So the same
job also runs `gh workflow run client-mobile-release.yml --ref vX.Y.Z` on the
tag it just created. This was measured, not reasoned: v1.36.0 (2026-09-18) was
dispatched before that hand-off existed and shipped with binaries and a signed
chart and no mobile artifact; v1.35.0 had both only because a maintainer
dispatched the mobile workflow by hand. `scripts/check-release-dispatch.sh`
holds this hand-off too.

Three consequences worth knowing: the images are stamped by the **docker.yml
run this dispatch starts** and the APK and IPA are attached by the
**client-mobile-release.yml run it starts**, not by the release run itself,
so check both before announcing; and the dispatched version is validated
(`vX.Y.Z`) rather than trusted, because unlike a pushed tag it is free-text
input.

## What the tag triggers (no manual steps)

- **`release.yml`** — runs the test suite, builds version-stamped Linux
  binaries (`-ldflags "-X main.Version=vX.Y.Z -X main.CommitHash=<sha>"`), and
  creates a GitHub Release with auto-generated notes and the binaries attached.
  A follow-on job packages the Helm chart (`--version X.Y.Z --app-version
  vX.Y.Z` — the committed `Chart.yaml` version is only the development
  version) and pushes it to `oci://ghcr.io/mhmtgngr/openidx/charts/openidx`,
  cosign-signed by digest.
- **`docker.yml`** — builds multi-arch (amd64/arm64) images, stamps the version
  via the `VERSION` build-arg, and the `release-tag` job re-tags each image
  `ghcr.io/mhmtgngr/openidx/<service>` with `X.Y.Z`, `X.Y`, `X`, `vX.Y.Z`,
  `vX.Y`, `vX` and `stable` — both spellings, pointing at one manifest. Pull
  either; `X.Y.Z` is the one this document and the chart use.
- **`client-mobile-release.yml`** — builds the mobile client and attaches
  `openidx-agent-android-vX.Y.Z[-debugsigned].apk` and
  `openidx-agent-ios-vX.Y.Z-unsigned.ipa` to the Release. The `-debugsigned`
  suffix and the `-unsigned` name say exactly what they say; the workflow's
  header explains both.
- **`display-equals-enforcement.yml`** — runs the tests that
  `docs/evidence/display-equals-enforcement.md` names against Postgres 16 and
  attaches `display-equals-enforcement-vX.Y.Z.md` to the Release. A test that
  fails, skips or does not run turns the run red. `release.yml` starts it on
  the tag once the Release exists, on both paths: a Release published under
  `GITHUB_TOKEN` starts no workflow by itself.

## Rolling out to cells (off by default)

A release does not deploy itself anywhere until the repository variable
`CELL_ROLLOUT` is `"true"`. With it set, `release.yml` runs the wave from the
global-scale plan (§4.3) after the chart is pushed and signed:

```
release ─┬─ helm-chart ─→ rollout-canary-1 ─→ rollout-eu-1 ─→ rollout-us-1
         └─ …
```

Each cell is one call of `.github/workflows/rollout-cell.yml`, running in the
GitHub environment `cell-<id>` (`cell-canary-1`, `cell-eu-1`, `cell-us-1`).
The environment holds that cell's `KUBECONFIG` (base64 of the kubeconfig
file) and is where a **required reviewer** goes in front of a production
cell — that reviewer is the canary bake until an automated SLO watch between
waves exists. The call is `helm upgrade --install --atomic`, layering
`values-prod.yaml` and then `deployments/kubernetes/cells/<id>.yaml`, which is
the only place a cell's `config.cellId` is set. A cell that does not come up
within the timeout is rolled back, its job fails, and the cells after it are
skipped, not attempted. After the upgrade the job reads `CELL_ID` back out of
the deployed ConfigMap and refuses a cell that does not answer with its own
name.

To add a cell: a values file under `deployments/kubernetes/cells/`, an
environment `cell-<id>` with `KUBECONFIG`, and a job in `release.yml` that
`needs` the cell before it. `scripts/check-release-rollout.sh` holds the
wave's shape: order, gate, atomic upgrade, environment, identity check.

## Verify

- The GitHub Release exists with notes, the binaries, and the signed
  checksums (`SHA256SUMS`, `SHA256SUMS.sig`, `SHA256SUMS.pem`).
- `ghcr.io/mhmtgngr/openidx/identity-service:X.Y.Z` (and the other services)
  are present.
- The chart resolves: `helm show chart
  oci://ghcr.io/mhmtgngr/openidx/charts/openidx --version X.Y.Z`.
- A deployed service reports the version: `GET /health` → `"version":"vX.Y.Z"`.
- The Release carries the APK and the IPA (on the dispatch path, from the
  `client-mobile-release.yml` run the release started).
- The Release carries `display-equals-enforcement-vX.Y.Z.md`, and its last
  line says **Passed**.

### Verifying downloaded binaries (consumers)

!!! note "Signing starts at v1.34.0"

    Cosign signing landed with the project-readiness programme, so **v1.34.0 is
    the first signed release**. Everything from v1.33.3 back has a
    `SHA256SUMS` but no `.sig`/`.pem`, and the recipes below will not verify
    against it — that is expected, not a tampering signal.

The release job signs `SHA256SUMS` with keyless cosign (Sigstore): the
signing certificate is minted from the workflow's GitHub OIDC identity, so
verification proves the checksums were produced by *this repository's
`release.yml`* — no key to distribute or leak. Then the checksum file
vouches for each binary:

```sh
cosign verify-blob \
  --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/mhmtgngr/openidx/\.github/workflows/release\.yml@' \
  SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

### Verifying the Helm chart (consumers)

The chart is an OCI artifact signed with the same workflow identity, so the
verification pin is identical — verify, then install by the same reference:

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/mhmtgngr/openidx/\.github/workflows/release\.yml@' \
  ghcr.io/mhmtgngr/openidx/charts/openidx:X.Y.Z
helm install openidx oci://ghcr.io/mhmtgngr/openidx/charts/openidx \
  --version X.Y.Z --namespace openidx --create-namespace
```

## Versioning policy

- **MAJOR** — incompatible API or config changes, or breaking DB migrations.
- **MINOR** — backwards-compatible features.
- **PATCH** — backwards-compatible bug/security fixes.

Database migrations are forward-only; take an RDS snapshot before a MAJOR
upgrade (see `docs/DEPLOYMENT.md`).
