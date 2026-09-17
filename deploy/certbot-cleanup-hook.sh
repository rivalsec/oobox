#!/usr/bin/env sh
# certbot --manual-cleanup-hook for oobox: clear the _acme-challenge TXT value.
set -eu

. "$(dirname "$0")/_api-url.sh"
API="$(oob_api_url)"
: "${OOB_API_KEY:?set OOB_API_KEY}"

curl -fsS -k \
  -H "Authorization: Bearer ${OOB_API_KEY}" \
  -H "Content-Type: application/json" \
  -X POST "${API}/acme/cleanup" \
  -d "{\"name\":\"_acme-challenge.${CERTBOT_DOMAIN}\"}" \
  >/dev/null || true
