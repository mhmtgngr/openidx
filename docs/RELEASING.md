# Releasing OpenIDX

OpenIDX follows [Semantic Versioning](https://semver.org): `vMAJOR.MINOR.PATCH`.
A release is cut by pushing a `vX.Y.Z` git tag — everything else is automated.

## Pre-flight

1. `main` is green (Go CI, Frontend CI, Docker Build, Helm, Terraform).
2. All PRs intended for the release are merged.
3. Update `CHANGELOG.md`: rename the `[Unreleased]` section to
   `[X.Y.Z] - YYYY-MM-DD` and start a fresh empty `[Unreleased]`.

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
- **`docker.yml`** — builds multi-arch (amd64/arm64) images, stamps the version
  via the `VERSION` build-arg, and the `release-tag` job re-tags each image
  `ghcr.io/mhmtgngr/openidx/<service>` with `X.Y.Z`, `X.Y`, `X`, and `stable`.

## Verify

- The GitHub Release exists with notes + binaries.
- `ghcr.io/mhmtgngr/openidx/identity-service:X.Y.Z` (and the other services)
  are present.
- A deployed service reports the version: `GET /health` → `"version":"vX.Y.Z"`.

## Versioning policy

- **MAJOR** — incompatible API or config changes, or breaking DB migrations.
- **MINOR** — backwards-compatible features.
- **PATCH** — backwards-compatible bug/security fixes.

Database migrations are forward-only; take an RDS snapshot before a MAJOR
upgrade (see `docs/DEPLOYMENT.md`).
