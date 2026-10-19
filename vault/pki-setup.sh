#!/usr/bin/env bash
# One-time Vault setup: PKI + device inventory (KV v2) + AWS IAM auth for Lambdas.
# Requires: VAULT_ADDR, VAULT_TOKEN (admin), jq.
set -euo pipefail

DOMAIN="iot.example.com"
VAULT_URL="https://vault.internal.example.com:8200"   # reachable from hubs (CRL)
ACCOUNT="111111111111"

# Lifetimes: Root 20y > Intermediate 10y > Hub 5y > Device 1y.
# A child cert can never outlive its issuer (Vault refuses), so keep this order.
# Plan: new intermediate under the same root around year 7–8; hubs get new certs on replacement.

# --- Root CA (prefer an offline root; here a separate mount) — 20 years ---
vault secrets enable -path=pki_root pki
vault secrets tune -max-lease-ttl=175200h pki_root
vault write -field=certificate pki_root/root/generate/internal \
  common_name="Example IoT Root CA" key_type=ec key_bits=384 ttl=175200h > root-ca.pem
vault write pki_root/config/urls \
  issuing_certificates="$VAULT_URL/v1/pki_root/ca" \
  crl_distribution_points="$VAULT_URL/v1/pki_root/crl"

# --- Issuing (intermediate) CA — 10 years ---
vault secrets enable -path=pki_iot pki
vault secrets tune -max-lease-ttl=87600h pki_iot
vault write -format=json pki_iot/intermediate/generate/internal \
  common_name="Example IoT Issuing CA" key_type=ec key_bits=256 | jq -r .data.csr > iot-int.csr
vault write -format=json pki_root/root/sign-intermediate csr=@iot-int.csr \
  format=pem_bundle ttl=87600h | jq -r .data.certificate > iot-int.pem
vault write pki_iot/intermediate/set-signed certificate=@iot-int.pem

# RouterOS uses CRL only (no OCSP); DER CRL at /v1/pki_iot/crl
# auto_rebuild: Vault rebuilds the CRL on a schedule, NOT on each revoke -> device-cert.sh
# calls pki_iot/crl/rotate right after revoking, then session_sync makes hubs re-download it.
vault write pki_iot/config/urls \
  issuing_certificates="$VAULT_URL/v1/pki_iot/ca" \
  crl_distribution_points="$VAULT_URL/v1/pki_iot/crl"
vault write pki_iot/config/crl expiry=48h auto_rebuild=true auto_rebuild_grace_period=12h
vault write pki_iot/config/auto-tidy enabled=true tidy_cert_store=true tidy_revoked_certs=true \
  safety_buffer=72h interval_duration=24h

# --- Device role: single device type. CN = <id>.iot.example.com (also the IKE ID).
# Devices without ECDSA support: use key_type=rsa key_bits=2048 (bigger IKE_AUTH
# packets -> more fragmentation risk on bad links; test first).
# "vpn" is reserved for the hub FQDN (vpn.$DOMAIN); device-cert.sh refuses that id.
vault write pki_iot/roles/iot-device \
  allowed_domains="$DOMAIN" allow_subdomains=true allow_bare_domains=false \
  allow_glob_domains=false allow_ip_sans=false enforce_hostnames=true \
  key_type=ec key_bits=256 server_flag=false client_flag=true \
  organization="Example" \
  use_csr_common_name=false use_csr_sans=false \
  ttl=8760h max_ttl=8760h

# --- Hub role: same FQDN on every hub, 5 years, no rotation.
# Each new hub instance gets a fresh cert at launch, so replacing hubs (AMI update /
# ASG instance refresh) renews them. Alarm on expiry as a safety net.
vault write pki_iot/roles/vpn-hub \
  allowed_domains="vpn.$DOMAIN" allow_bare_domains=true allow_subdomains=false \
  key_type=ec key_bits=256 server_flag=true client_flag=false \
  ttl=43800h max_ttl=43800h

# --- Device inventory (replaces DynamoDB): kv/iot-devices/<id> = serial, cn, status
vault secrets enable -path=kv -version=2 kv || true

# --- Policies ---
vault policy write hub-provisioner - <<'EOF'
path "pki_iot/issue/vpn-hub"  { capabilities = ["update"] }
path "pki_iot/cert/ca_chain"  { capabilities = ["read"] }
EOF

vault policy write iot-operator - <<'EOF'
path "pki_iot/issue/iot-*"             { capabilities = ["update"] }
path "pki_iot/sign/iot-*"              { capabilities = ["update"] }
path "pki_iot/revoke"                  { capabilities = ["update"] }
path "pki_iot/crl/rotate"              { capabilities = ["read"] }   # rebuild CRL right after revoke
path "pki_iot/certs"                   { capabilities = ["list"] }
path "pki_iot/cert/*"                  { capabilities = ["read"] }
path "kv/data/iot-devices/*"           { capabilities = ["create", "read", "update", "patch"] }
path "kv/metadata/iot-devices/*"       { capabilities = ["list", "read"] }
path "kv/metadata/iot-devices"         { capabilities = ["list"] }
EOF

# --- AWS IAM auth: only the hub_lifecycle Lambda role gets hub certs ---
vault auth enable aws || true
vault write auth/aws/role/hub-provisioner auth_type=iam \
  bound_iam_principal_arn="arn:aws:iam::$ACCOUNT:role/iot-hub-lifecycle" \
  token_policies=hub-provisioner token_ttl=15m token_max_ttl=30m

echo "Done. Trust anchors for devices: root-ca.pem + iot-int.pem"
