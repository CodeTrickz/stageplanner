#!/usr/bin/env bash
set -euo pipefail

# Simple cache/ETag smoke test for backend GET endpoints.
#
# Usage:
#   API_URL=http://localhost:3001 \
#   TOKEN=YOUR_JWT \
#   WORKSPACE_ID=WORKSPACE_UUID \
#   ./testscripts/cache-smoke.sh
#
# Optional:
#   DATE=2026-01-21

API_URL="${API_URL:-http://localhost:3001}"
TOKEN="${TOKEN:-}"
WORKSPACE_ID="${WORKSPACE_ID:-}"
DATE="${DATE:-}"

if [[ -z "$TOKEN" || -z "$WORKSPACE_ID" ]]; then
  echo "Missing TOKEN or WORKSPACE_ID."
  echo "Example: API_URL=http://localhost:3001 TOKEN=... WORKSPACE_ID=... ./testscripts/cache-smoke.sh"
  exit 1
fi

auth_header="Authorization: Bearer ${TOKEN}"

echo "== Planning =="
planning_query="workspaceId=${WORKSPACE_ID}"
if [[ -n "$DATE" ]]; then
  planning_query="${planning_query}&date=${DATE}"
fi

planning_headers_1="$(mktemp)"
planning_headers_2="$(mktemp)"
planning_body="$(mktemp)"

curl -sS -D "$planning_headers_1" -o "$planning_body" \
  -H "$auth_header" \
  "${API_URL}/planning?${planning_query}" >/dev/null

etag_planning="$(grep -i '^etag:' "$planning_headers_1" | awk '{print $2}' | tr -d $'\r')"
if [[ -z "$etag_planning" ]]; then
  echo "No ETag for planning response."
  exit 1
fi

curl -sS -D "$planning_headers_2" -o /dev/null \
  -H "$auth_header" \
  -H "If-None-Match: ${etag_planning}" \
  "${API_URL}/planning?${planning_query}" >/dev/null

planning_status="$(head -n 1 "$planning_headers_2" | awk '{print $2}')"
echo "Planning status (with If-None-Match): ${planning_status}"

echo "== Notes =="
notes_headers_1="$(mktemp)"
notes_headers_2="$(mktemp)"

curl -sS -D "$notes_headers_1" -o /dev/null \
  -H "$auth_header" \
  "${API_URL}/notes?workspaceId=${WORKSPACE_ID}" >/dev/null

etag_notes="$(grep -i '^etag:' "$notes_headers_1" | awk '{print $2}' | tr -d $'\r')"
if [[ -z "$etag_notes" ]]; then
  echo "No ETag for notes response."
  exit 1
fi

curl -sS -D "$notes_headers_2" -o /dev/null \
  -H "$auth_header" \
  -H "If-None-Match: ${etag_notes}" \
  "${API_URL}/notes?workspaceId=${WORKSPACE_ID}" >/dev/null

notes_status="$(head -n 1 "$notes_headers_2" | awk '{print $2}')"
echo "Notes status (with If-None-Match): ${notes_status}"

echo "== Files =="
files_headers_1="$(mktemp)"
files_headers_2="$(mktemp)"

curl -sS -D "$files_headers_1" -o /dev/null \
  -H "$auth_header" \
  "${API_URL}/files?workspaceId=${WORKSPACE_ID}" >/dev/null

etag_files="$(grep -i '^etag:' "$files_headers_1" | awk '{print $2}' | tr -d $'\r')"
if [[ -z "$etag_files" ]]; then
  echo "No ETag for files response."
  exit 1
fi

curl -sS -D "$files_headers_2" -o /dev/null \
  -H "$auth_header" \
  -H "If-None-Match: ${etag_files}" \
  "${API_URL}/files?workspaceId=${WORKSPACE_ID}" >/dev/null

files_status="$(head -n 1 "$files_headers_2" | awk '{print $2}')"
echo "Files status (with If-None-Match): ${files_status}"

rm -f "$planning_headers_1" "$planning_headers_2" "$planning_body" \
  "$notes_headers_1" "$notes_headers_2" \
  "$files_headers_1" "$files_headers_2"

echo "Done."
