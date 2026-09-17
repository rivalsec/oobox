#!/usr/bin/env sh
# certbot --deploy-hook for oobox: runs as root after every successful issue/renewal.
#
# Two things break on renewal without this:
#   1. certbot ships /etc/letsencrypt/{live,archive} as 0700 root, so the non-root
#      service user cannot read the cert at all. Worse, renewal writes NEW files into
#      archive/<domain>/ (cert2.pem, privkey2.pem, ...) and repoints the live/ symlinks
#      at them, so a one-off chmod/setfacl over the existing files stops covering them.
#   2. oobox loads the cert into an SSLContext once, at startup — a running process
#      keeps serving the old cert until it is restarted.
#
# Install:
#   sudo install -m 755 deploy/certbot-deploy-hook.sh /etc/letsencrypt/renewal-hooks/deploy/oobox
#   sudo /etc/letsencrypt/renewal-hooks/deploy/oobox     # apply now
# It then runs automatically on every `certbot renew`.
set -eu

USER_NAME="${OOBOX_USER:-oobox}"
GROUP_NAME="${OOBOX_GROUP:-$USER_NAME}"
UNIT="${OOBOX_UNIT:-oobox}"
ENV_FILE="${OOBOX_ENV:-/etc/oobox/env}"

LIVE=/etc/letsencrypt/live
ARCHIVE=/etc/letsencrypt/archive

# certbot sets RENEWED_LINEAGE; when run by hand it is unset, so fall back to OOBDOMAIN.
lineage="${RENEWED_LINEAGE:-}"
if [ -z "$lineage" ]; then
    domain="${OOBOX_DOMAIN:-}"
    if [ -z "$domain" ] && [ -r "$ENV_FILE" ]; then
        domain=$(sed -n 's/^[[:space:]]*\(export[[:space:]]\+\)\?OOBDOMAIN=//p' "$ENV_FILE" \
                 | tr -d "\"'" | tail -1)
    fi
    [ -n "$domain" ] || { echo "hook: set OOBOX_DOMAIN=, or OOBDOMAIN in $ENV_FILE" >&2; exit 1; }
    lineage="$LIVE/$domain"
fi
name=$(basename "$lineage")
[ -d "$lineage" ] || { echo "hook: no cert directory at $lineage" >&2; exit 1; }

# Grant traversal (x) on the shared parents but read (rX) only on this lineage, so the
# service user cannot read other domains' private keys on the same box.
if command -v setfacl >/dev/null 2>&1; then
    setfacl -m "u:${USER_NAME}:x" "$LIVE" "$ARCHIVE"
    for d in "$lineage" "$ARCHIVE/$name"; do
        [ -d "$d" ] || continue
        setfacl -R  -m "u:${USER_NAME}:rX" "$d"
        setfacl -dR -m "u:${USER_NAME}:rX" "$d"   # inherited by files renewals create
    done
else
    # No acl package (apt-get install -y acl). Group ownership does the same job; this
    # hook re-applying it on every renewal is what keeps it working over time.
    chgrp "$GROUP_NAME" "$LIVE" "$ARCHIVE"
    chmod g+x "$LIVE" "$ARCHIVE"                  # traverse, but not list
    for d in "$lineage" "$ARCHIVE/$name"; do
        [ -d "$d" ] || continue
        chgrp -R "$GROUP_NAME" "$d"
        chmod -R g+rX "$d"
    done
fi

systemctl restart "$UNIT"
