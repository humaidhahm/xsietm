#!/usr/bin/env bash
# =============================================================================
#  deploy.sh - bring up the Wazuh single-node stack for the XSIEM lab.
#
#  Nothing in this script contains a secret. Every credential comes from the
#  environment (a .env file in the compose directory, or exported variables).
#
#  Usage:
#      cd compose
#      cp ../../.env.example .env && $EDITOR .env     # fill it in
#      set -a; . ./.env; set +a
#      ./deploy.sh
#
#  What it does:
#      1. checks every required credential is present
#      2. generates the indexer/manager/dashboard certificates (first run only)
#      3. issues the manager's authd TLS certificate from the generated root CA
#         (the stock Wazuh image ships an EXPIRED self-signed cert, which blocks
#         agent enrolment - see docs/GROUND-TRUTH.md)
#      4. renders the dashboard's wazuh.yml from a template
#      5. starts the stack and waits for the indexer to be healthy
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")"

CERT_DIR="config/wazuh_indexer_ssl_certs"
DASH_DIR="config/wazuh_dashboard"

say()  { printf '\033[36m[deploy]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[deploy] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }
ok()   { printf '\033[32m[deploy]\033[0m %s\n' "$*"; }

# --------------------------------------------------------------- 1. secrets --
say "checking required environment variables"
missing=()
for v in WAZUH_INDEXER_USER WAZUH_INDEXER_PASSWORD \
         WAZUH_API_USER WAZUH_API_PASSWORD \
         WAZUH_DASHBOARD_USER WAZUH_DASHBOARD_PASSWORD; do
  if [[ -z "${!v:-}" ]]; then missing+=("$v"); fi
done
if [[ ${#missing[@]} -gt 0 ]]; then
  printf '\033[31m[deploy] FATAL:\033[0m missing required environment variable(s):\n' >&2
  printf '            %s\n' "${missing[@]}" >&2
  printf '  Create compose/.env from ../../.env.example and fill it in:\n' >&2
  printf '      cp ../../.env.example .env && $EDITOR .env\n' >&2
  printf '  then:  set -a; . ./.env; set +a\n' >&2
  exit 1
fi
ok "all credentials present"

# ---------------------------------------------------------- 2. certificates --
if [[ ! -f "$CERT_DIR/root-ca.pem" || ! -f "$CERT_DIR/root-ca.key" ]]; then
  say "generating the indexer certificates (first run)"
  mkdir -p "$CERT_DIR"
  docker compose -f generate-indexer-certs.yml run --rm generator
  ok "certificates generated"
else
  say "certificates already present - skipping generation"
fi

# ------------------------------------------- 3. manager authd TLS certificate --
# The Wazuh manager image ships a self-signed certificate that expired on
# 2025-11-05. An agent trying to enrol on 1515 fails with
#   "Problem with certificate at depth 0" / "certificate has expired".
# We issue a replacement from the root CA that was just generated, so the
# endpoint can trust the manager's CA with no change on the endpoint side.
if [[ ! -f "$CERT_DIR/manager-authd.pem" || ! -f "$CERT_DIR/manager-authd-key.pem" ]]; then
  say "issuing the manager authd TLS certificate from the root CA"
  command -v openssl >/dev/null || die "openssl is required"
  VM_IP="${XSIEM_SERVER:-$(ip -4 -o addr show scope global eth0 | awk '{print $4}' | cut -d/ -f1)}"
  EXT="$(mktemp)"
  cat > "$EXT" <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names

[alt_names]
DNS.1 = wazuh.manager
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ${VM_IP}
EOF
  openssl genrsa -out "$CERT_DIR/manager-authd-key.pem" 2048 2>/dev/null
  openssl req -new -key "$CERT_DIR/manager-authd-key.pem" -out /tmp/manager-authd.csr \
    -subj "/C=US/ST=California/O=Wazuh/OU=Wazuh/CN=wazuh.manager"
  openssl x509 -req -in /tmp/manager-authd.csr -CA "$CERT_DIR/root-ca.pem" \
    -CAkey "$CERT_DIR/root-ca.key" -CAcreateserial -out "$CERT_DIR/manager-authd.pem" \
    -days 3650 -sha256 -extfile "$EXT" 2>/dev/null
  rm -f "$EXT" /tmp/manager-authd.csr
  chmod 640 "$CERT_DIR/manager-authd.pem" "$CERT_DIR/manager-authd-key.pem"
  ok "manager authd certificate issued (valid 10 years, signed by the root CA)"
else
  say "manager authd certificate already present"
fi

# --------------------------------------------------- 4. dashboard wazuh.yml --
say "rendering the dashboard configuration"
mkdir -p "$DASH_DIR"
sed "s|\${WAZUH_API_PASSWORD}|${WAZUH_API_PASSWORD}|g" \
    "$DASH_DIR/wazuh.yml.template" > "$DASH_DIR/wazuh.yml"
chmod 640 "$DASH_DIR/wazuh.yml"
ok "dashboard configuration rendered"

# ------------------------------------------------------------- 5. start up --
say "starting the stack"
sysctl -w vm.max_map_count=262144 >/dev/null
docker compose up -d

say "waiting for the indexer to become healthy"
for i in $(seq 1 60); do
  status="$(curl -sk -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASSWORD}" \
            https://localhost:9200/_cluster/health 2>/dev/null | jq -r '.status // empty' 2>/dev/null || true)"
  if [[ "$status" == "green" || "$status" == "yellow" ]]; then
    ok "indexer is $status after $((i * 5))s"
    break
  fi
  [[ $((i % 6)) -eq 0 ]] && printf '.'
  sleep 5
done
[[ "${status:-}" == "green" || "${status:-}" == "yellow" ]] || die "the indexer did not become healthy"

echo
docker compose ps
echo
ok "stack is up."
echo "    Wazuh dashboard : https://localhost/          (${WAZUH_DASHBOARD_USER} / see .env)"
echo "    Wazuh API       : https://localhost:55000     (${WAZUH_API_USER} / see .env)"
echo "    Indexer         : https://localhost:9200      (${WAZUH_INDEXER_USER} / see .env)"
echo
echo "  Next: start the backend and the dashboard (see the root README.md)."
