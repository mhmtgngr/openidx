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
   console, the Helm chart's `appVersion`, the Flutter client and all ten
   OpenAPI specs to that number.

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

Two consequences worth knowing: the images are stamped by the **docker.yml run
this dispatch starts**, not by the release run itself, so check that run before
announcing; and the dispatched version is validated (`vX.Y.Z`) rather than
trusted, because unlike a pushed tag it is free-text input.

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
  `ghcr.io/mhmtgngr/openidx/<service>` with `X.Y.Z`, `X.Y`, `X`, and `stable`.

## Verify

- The GitHub Release exists with notes, the binaries, and the signed
  checksums (`SHA256SUMS`, `SHA256SUMS.sig`, `SHA256SUMS.pem`).
- `ghcr.io/mhmtgngr/openidx/identity-service:X.Y.Z` (and the other services)
  are present.
- The chart resolves: `helm show chart
  oci://ghcr.io/mhmtgngr/openidx/charts/openidx --version X.Y.Z`.
- A deployed service reports the version: `GET /health` → `"version":"vX.Y.Z"`.

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
