#!/usr/bin/env bash
# lite-ci-images.sh — build the lite install's images from this checkout.
#
# Usage: scripts/lite-ci-images.sh [registry] [tag]      (default: openidx-ci ci)
# Then:  OPENIDX_IMAGE_REGISTRY=openidx-ci OPENIDX_VERSION=ci ./scripts/lite-up.sh
#
# The lite compose file pins the published release images, which is right for
# someone installing OpenIDX and useless for testing a pull request: they hold
# the last release's code, not this commit's. This builds every image the lite
# file names, from this checkout, under the names the file composes from
# OPENIDX_IMAGE_REGISTRY and OPENIDX_VERSION:
#
#   - the seven services and migrate: `go build` here, wrapped in the release
#     runtime (deployments/ci/lite/Dockerfile.prebuilt explains why);
#   - the console: the real Dockerfile.admin-console, production stage, so the
#     nginx image and its non-root user are the ones a release ships.
#
# Needs Go (the version go.mod pins) and Docker. Base-image pulls are retried,
# because Docker Hub's outages are not this commit's defects.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REGISTRY="${1:-openidx-ci}"
TAG="${2:-ci}"
SERVICES="identity-service governance-service provisioning-service audit-service admin-api oauth-service access-service"
RETRY=(bash scripts/ci-retry.sh 3 10 --)

ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
mkdir -p "$ctx/bin"

version="lite-ci-$(git rev-parse --short=12 HEAD 2>/dev/null || echo local)"
start=$SECONDS
for bin in $SERVICES migrate; do
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=$version" -o "$ctx/bin/$bin" "./cmd/$bin"
done
echo "lite-ci-images: compiled $SERVICES migrate in $((SECONDS - start))s"
cp deployments/docker/entrypoint-access.sh "$ctx/entrypoint-access.sh"

dockerfile="deployments/ci/lite/Dockerfile.prebuilt"
for svc in $SERVICES; do
  if [ "$svc" = "access-service" ]; then
    "${RETRY[@]}" docker build -q -f "$dockerfile" --target access -t "$REGISTRY/$svc:$TAG" "$ctx"
  else
    "${RETRY[@]}" docker build -q -f "$dockerfile" --target service --build-arg "SERVICE=$svc" -t "$REGISTRY/$svc:$TAG" "$ctx"
  fi
done
"${RETRY[@]}" docker build -q -f "$dockerfile" --target tools -t "$REGISTRY/tools:$TAG" "$ctx"

start=$SECONDS
"${RETRY[@]}" docker build -f deployments/docker/Dockerfile.admin-console --target production \
  -t "$REGISTRY/admin-console:$TAG" .
echo "lite-ci-images: built the console image in $((SECONDS - start))s"

docker image ls --format '{{.Repository}}:{{.Tag}}\t{{.Size}}' | grep "^$REGISTRY/" | sort
