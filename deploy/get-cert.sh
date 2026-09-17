#!/usr/bin/env bash
# Issue (or renew) the wildcard cert for OOBDOMAIN via ACME DNS-01, self-answered by
# the running oobox DNS listener. oobox MUST already be running (it serves the
# challenge TXT) and its NS must be delegated to this box.
#
# Usage:  OOBDOMAIN=oob.example.com OOB_API_KEY=... deploy/get-cert.sh [--staging]
#
# On success certbot writes to /etc/letsencrypt/live/$OOBDOMAIN/; point
# OOB_TLS_CERT/OOB_TLS_KEY there (or copy into deploy/certs for the container) and
# restart oobox so HTTPS + API TLS come up.
set -euo pipefail

: "${OOBDOMAIN:?set OOBDOMAIN}"
: "${OOB_API_KEY:?set OOB_API_KEY}"
. "$(dirname "$0")/_api-url.sh"
# Probe once here and pass it down, so the hooks do not each re-probe.
OOB_API_URL="$(oob_api_url)"
export OOB_API_KEY OOB_API_URL

HERE="$(cd "$(dirname "$0")" && pwd)"
EXTRA=()
STAGING=0
[[ "${1:-}" == "--staging" ]] && { EXTRA+=(--staging); STAGING=1; }

RENEWAL_CONF="/etc/letsencrypt/renewal/${OOBDOMAIN}.conf"
LIVE="/etc/letsencrypt/live/${OOBDOMAIN}/fullchain.pem"

# Which ACME server does the existing lineage belong to? certbot records it in the
# renewal conf as plain text, so this needs no openssl binary (that is deliberate —
# a minimal server image may not have one, and a check that silently fails open is
# worse than no check). Echoes: staging | production | none | unknown
lineage_kind() {
    if [[ -r "$RENEWAL_CONF" ]]; then
        if grep -qi 'acme-staging' "$RENEWAL_CONF"; then echo staging; else echo production; fi
    elif [[ -e "$RENEWAL_CONF" || -e "$LIVE" ]]; then
        echo unknown          # it exists but we cannot read it — are we root?
    else
        echo none
    fi
}

# A staging lineage blocks its own replacement: certbot sees a cert that is valid for
# these domains and answers "not yet due for renewal", so a production run is a silent
# no-op and the server keeps serving a cert no client trusts.
KIND="$(lineage_kind)"
if [[ $STAGING -eq 0 && "$KIND" == staging ]]; then
    echo "ERROR: the existing lineage for ${OOBDOMAIN} is a STAGING one." >&2
    echo "certbot would report 'not yet due for renewal' and change nothing. Delete it first:" >&2
    echo "  sudo certbot delete --cert-name ${OOBDOMAIN}" >&2
    exit 1
fi
if [[ "$KIND" == unknown ]]; then
    echo "ERROR: cannot read ${RENEWAL_CONF} — re-run with sudo." >&2
    exit 1
fi

LOG="$(mktemp)"; trap 'rm -f "$LOG"' EXIT
certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook "${HERE}/certbot-auth-hook.sh" \
  --manual-cleanup-hook "${HERE}/certbot-cleanup-hook.sh" \
  --non-interactive --agree-tos --register-unsafely-without-email \
  -d "${OOBDOMAIN}" -d "*.${OOBDOMAIN}" \
  "${EXTRA[@]}" 2>&1 | tee "$LOG"

echo
# certbot exits 0 when it decides there is nothing to do, so say what actually happened
# rather than claiming an issuance that did not occur.
if grep -qi 'not yet due for renewal' "$LOG"; then
    echo "NOTE: certbot made no change — the existing cert is still valid."
    echo "      To replace it before expiry: sudo certbot delete --cert-name ${OOBDOMAIN}, then re-run."
else
    echo "Cert issued at /etc/letsencrypt/live/${OOBDOMAIN}/"
fi

if [[ "$(lineage_kind)" == staging ]]; then
    echo
    echo "WARNING: ${OOBDOMAIN} is signed by Let's Encrypt's STAGING CA, which is in no"
    echo "trust store — every client will reject it. Good for rehearsing DNS-01 only."
    echo "For a real cert:  sudo certbot delete --cert-name ${OOBDOMAIN} && $0"
    exit 1
fi

echo
echo "Bare-metal/systemd: oobox auto-detects this path, but certbot ships these dirs"
echo "0700 root — the oobox service user cannot read them until you grant access:"
echo "  sudo install -m 755 deploy/certbot-deploy-hook.sh /etc/letsencrypt/renewal-hooks/deploy/oobox"
echo "  sudo /etc/letsencrypt/renewal-hooks/deploy/oobox   # grants access + restarts now"
echo "That hook also re-grants and restarts on every future renewal."
echo
echo "Docker / custom path: set and mount the cert, then restart:"
echo "  OOB_TLS_CERT=/etc/letsencrypt/live/${OOBDOMAIN}/fullchain.pem"
echo "  OOB_TLS_KEY=/etc/letsencrypt/live/${OOBDOMAIN}/privkey.pem"
