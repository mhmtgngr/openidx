#!/usr/bin/env bash
# backup-elasticsearch.sh — Create an Elasticsearch snapshot for audit data
#
# Usage:
#   ./scripts/backup-elasticsearch.sh
#
# Environment variables:
#   ES_URL            Elasticsearch URL         (default: http://localhost:9200)
#   ES_REPO_NAME      Snapshot repository name  (default: openidx-backups)
#   ES_REPO_PATH      Shared filesystem path    (default: /usr/share/elasticsearch/backups)
#   ES_INDICES        Indices to snapshot        (default: openidx-audit-*)

set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"
ES_REPO_NAME="${ES_REPO_NAME:-openidx-backups}"
ES_REPO_PATH="${ES_REPO_PATH:-/usr/share/elasticsearch/backups}"
ES_INDICES="${ES_INDICES:-openidx-audit-*}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SNAPSHOT_NAME="snapshot_${TIMESTAMP}"

echo "==> Checking Elasticsearch connectivity ..."
if ! curl -sf "${ES_URL}/_cluster/health" > /dev/null 2>&1; then
  echo "ERROR: Cannot reach Elasticsearch at ${ES_URL}" >&2
  exit 1
fi

echo "==> Ensuring snapshot repository '${ES_REPO_NAME}' exists ..."
curl -sf -X PUT "${ES_URL}/_snapshot/${ES_REPO_NAME}" \
  -H 'Content-Type: application/json' \
  -d "{
    \"type\": \"fs\",
    \"settings\": {
      \"location\": \"${ES_REPO_PATH}\",
      \"compress\": true
    }
  }" > /dev/null

echo "==> Creating snapshot '${SNAPSHOT_NAME}' for indices '${ES_INDICES}' ..."
RESPONSE=$(curl -sf -X PUT "${ES_URL}/_snapshot/${ES_REPO_NAME}/${SNAPSHOT_NAME}?wait_for_completion=true" \
  -H 'Content-Type: application/json' \
  -d "{
    \"indices\": \"${ES_INDICES}\",
    \"ignore_unavailable\": true,
    \"include_global_state\": false
  }")

STATE=$(echo "$RESPONSE" | grep -o '"state":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ "$STATE" = "SUCCESS" ]; then
  echo "==> Snapshot complete: ${ES_REPO_NAME}/${SNAPSHOT_NAME} (state: ${STATE})"
else
  echo "ERROR: Snapshot state: ${STATE}" >&2
  echo "$RESPONSE" >&2
  exit 1
fi
