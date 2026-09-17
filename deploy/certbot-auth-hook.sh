#!/usr/bin/env sh
# certbot --manual-auth-hook for oobox.
#
# certbot calls this with CERTBOT_DOMAIN + CERTBOT_VALIDATION set. We register the
# _acme-challenge TXT value with oobox's control API; the running DNS listener then
# answers it directly, so Let's Encrypt sees it immediately (no propagation wait —
# this box IS the authoritative NS).
#
# Env:
#   OOB_API_URL   control API base (default: probed, https then http)
#   OOB_API_KEY   bearer key (required)
set -eu

. "$(dirname "$0")/_api-url.sh"
API="$(oob_api_url)"
: "${OOB_API_KEY:?set OOB_API_KEY}"

curl -fsS -k \
  -H "Authorization: Bearer ${OOB_API_KEY}" \
  -H "Content-Type: application/json" \
  -X POST "${API}/acme/present" \
  -d "{\"name\":\"_acme-challenge.${CERTBOT_DOMAIN}\",\"value\":\"${CERTBOT_VALIDATION}\"}" \
  >/dev/null

# tiny settle so the value is live before certbot asks the ACME server to check
sleep 1
