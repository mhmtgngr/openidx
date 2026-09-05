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
