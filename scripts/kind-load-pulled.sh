#!/usr/bin/env bash
# kind-load-pulled.sh IMAGE CLUSTER — load an image pulled from a registry into
# a kind cluster, one platform only.
#
# `kind load docker-image` runs `docker save | ctr images import
# --all-platforms`. With Docker's containerd image store (the default since
# Docker 29, which the ubuntu runners now ship), a pulled multi-platform image
# keeps its whole index but only the host platform's blobs, so the import dies
# with "ctr: content digest ...: not found" before anything is installed
# (kubernetes-sigs/kind#3795). Saving just the host's platform and loading that
# archive works with both image stores. An image built locally is single
# platform already and keeps using `kind load docker-image`.
set -euo pipefail

img=${1:?image}
cluster=${2:?cluster name}
platform=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')
archive=$(mktemp "${RUNNER_TEMP:-/tmp}/kind-load.XXXXXX.tar")
trap 'rm -f "$archive"' EXIT

if docker image save --help 2>/dev/null | grep -q -- '--platform'; then
  docker image save --platform "$platform" -o "$archive" "$img"
else
  docker image save -o "$archive" "$img"
fi
kind load image-archive "$archive" --name "$cluster"
