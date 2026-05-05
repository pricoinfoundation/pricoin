#!/usr/bin/env bash
#
# Pricoin relay one-shot installer. Run as root on each of rpc1..rpc4.
# Sets up: strfry build + install, dedicated user, LMDB dir, systemd
# units (relay + cross-streams), nginx vhost for the per-node
# relay<N>.pricoin.io, and Let's Encrypt cert via certbot --nginx.
#
# Usage:
#   ./install.sh <self-hostname> <peer1> <peer2> <peer3>
# e.g. on rpc1:
#   ./install.sh relay1.pricoin.io \
#       relay2.pricoin.io relay3.pricoin.io relay4.pricoin.io
#
# Pre-reqs:
#   * DNS for each relay<N>.pricoin.io must already point at this
#     box (Let's Encrypt HTTP-01 challenge needs a working :80).
#   * nginx must already be installed and serving (we add a vhost,
#     not the whole stack).
#
# Idempotent — re-runs are safe.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root."
    exit 1
fi
if [[ $# -ne 4 ]]; then
    echo "Usage: $0 <self-hostname> <peer1> <peer2> <peer3>"
    exit 1
fi

SELF_HOST="$1"
PEER1="$2"
PEER2="$3"
PEER3="$4"

DIR="$(cd "$(dirname "$0")" && pwd)"
# strfry tag/branch — leave empty for master (default).
STRFRY_VERSION_TAG="${STRFRY_VERSION_TAG:-}"

# ─── 1. Build/runtime packages ───────────────────────────────────
apt-get update -qq
apt-get install -y --no-install-recommends \
    git build-essential pkg-config \
    libssl-dev libb2-dev liblmdb-dev libflatbuffers-dev \
    libsecp256k1-dev libzstd-dev zlib1g-dev libtool \
    jq ca-certificates \
    nginx certbot python3-certbot-nginx

# ─── 2. strfry: clone + build + install ──────────────────────────
if ! [[ -x /usr/local/bin/strfry ]]; then
    cd /tmp
    rm -rf strfry-src
    git clone https://github.com/hoytech/strfry.git strfry-src
    cd strfry-src
    if [[ -n "${STRFRY_VERSION_TAG}" ]]; then
        git checkout "${STRFRY_VERSION_TAG}"
    fi
    git submodule update --init --recursive
    make setup-golpe
    make -j"$(nproc)"
    install -m 0755 strfry /usr/local/bin/strfry
fi

# ─── 3. User + dirs ──────────────────────────────────────────────
id -u pricoin-relay >/dev/null 2>&1 || useradd --system --no-create-home \
    --shell /usr/sbin/nologin --home-dir /var/lib/pricoin-relay pricoin-relay
install -d -o pricoin-relay -g pricoin-relay -m 0750 /var/lib/pricoin-relay/db
install -d -o pricoin-relay -g pricoin-relay -m 0750 /var/log/pricoin-relay
install -d -m 0755 /etc/pricoin-relay
install -d -m 0755 /usr/local/lib/pricoin-relay
install -d -m 0755 /var/www/certbot

# ─── 4. Config + writepolicy ─────────────────────────────────────
sed "s|RELAY_HOSTNAME_HERE|${SELF_HOST}|g; s|RELAY_URL_HERE|${SELF_HOST}|g" \
    "${DIR}/strfry.conf" > /etc/pricoin-relay/strfry.conf
chown root:pricoin-relay /etc/pricoin-relay/strfry.conf
chmod 0640 /etc/pricoin-relay/strfry.conf

install -m 0755 "${DIR}/writepolicy.sh" /usr/local/lib/pricoin-relay/writepolicy.sh

# ─── 5. Systemd units ────────────────────────────────────────────
install -m 0644 "${DIR}/pricoin-relay.service"          /etc/systemd/system/
install -m 0644 "${DIR}/pricoin-relay-stream@.service"  /etc/systemd/system/

# ─── 6. nginx vhost: phase 1 (HTTP-only ACME challenge) ─────────
# Drop the HTTP-only vhost first so certbot's webroot challenge
# works without trying to deal with non-existent TLS certs.
sed "s|RELAY_HOSTNAME_HERE|${SELF_HOST}|g" \
    "${DIR}/nginx-relay-acme.conf" > /etc/nginx/sites-available/pricoin-relay
ln -sf /etc/nginx/sites-available/pricoin-relay /etc/nginx/sites-enabled/pricoin-relay
nginx -t
systemctl reload nginx

# ─── 7. Obtain LE cert via webroot ──────────────────────────────
# Idempotent: certbot reports "Certificate not yet due for renewal"
# on re-runs and exits 0.
LE_DIR="/etc/letsencrypt/live/${SELF_HOST}"
if [[ ! -f "${LE_DIR}/fullchain.pem" ]]; then
    if ! certbot certonly --webroot -w /var/www/certbot \
        --non-interactive --agree-tos \
        --email "ops@pricoin.io" \
        -d "${SELF_HOST}"; then
        echo "ERROR: certbot failed; check DNS resolution + :80 reachability"
        echo "       for ${SELF_HOST}, then re-run this installer."
        exit 1
    fi
fi

# ─── 8. nginx vhost: phase 2 (full HTTPS reverse proxy) ─────────
sed "s|RELAY_HOSTNAME_HERE|${SELF_HOST}|g" \
    "${DIR}/nginx-relay.conf" > /etc/nginx/sites-available/pricoin-relay
nginx -t
systemctl reload nginx

# ─── 8. Start relay + stream daemons ─────────────────────────────
systemctl daemon-reload
systemctl enable --now pricoin-relay.service
for peer in "${PEER1}" "${PEER2}" "${PEER3}"; do
    systemctl enable --now "pricoin-relay-stream@${peer}.service"
done

# ─── 9. Sanity check ─────────────────────────────────────────────
sleep 2
echo
echo "── Status ─────────────────────────────────────────────"
systemctl --no-pager --lines=0 status pricoin-relay.service || true
for peer in "${PEER1}" "${PEER2}" "${PEER3}"; do
    systemctl --no-pager --lines=0 status "pricoin-relay-stream@${peer}.service" || true
done
echo
echo "── NIP-11 info doc (expect JSON) ──────────────────────"
curl --max-time 5 -sS -H 'Accept: application/nostr+json' \
    "https://${SELF_HOST}/" | head -c 400
echo
