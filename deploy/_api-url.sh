# shellcheck shell=sh
# Sourced by get-cert.sh and the certbot hooks. Not executable on its own.
#
# Resolve the oobox control API base URL. The scheme is NOT fixed: oobox serves the
# API over TLS whenever a cert is configured (api_tls() falls back to OOB_TLS_CERT,
# which auto-detects the Let's Encrypt path), and plaintext otherwise. So a hardcoded
# http:// breaks the moment TLS starts working — an HTTP request to the TLS socket
# comes back as "curl: (52) Empty reply from server", the TXT never gets registered,
# and DNS-01 fails with "No TXT record found". Probe the unauthenticated /healthz
# instead. -k because the cert being served may be the very one we are issuing.
oob_api_url() {
    if [ -n "${OOB_API_URL:-}" ]; then printf '%s' "${OOB_API_URL}"; return 0; fi
    _host="127.0.0.1:${OOB_API_PORT:-8443}"
    for _scheme in https http; do
        # Judge by the HTTP status, not curl's exit code: a server that ends the TLS
        # session without close_notify makes curl exit 56 *after* a complete response,
        # which would otherwise look like a failed probe. A scheme mismatch gives 000.
        # The || true matters under `set -e` in the sourcing script.
        _code=$(curl -s -k -m 5 -o /dev/null -w '%{http_code}' \
                "${_scheme}://${_host}/healthz" 2>/dev/null || true)
        if [ "${_code}" = "200" ]; then
            printf '%s' "${_scheme}://${_host}"
            return 0
        fi
    done
    echo "cannot reach the oobox control API on ${_host} — is oobox running?" >&2
    return 1
}
