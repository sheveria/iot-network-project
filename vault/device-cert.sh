#!/usr/bin/env bash
# IoT device certificate lifecycle. Certificates AND keys are generated centrally in Vault.
#
#   device-cert.sh issue  <device-id>             new device: key + cert + CA + client config
#   device-cert.sh bulk   <devices.csv>           many devices; one device-id per line
#   device-cert.sh renew  <device-id>             new key + cert for existing device (old stays valid)
#   device-cert.sh revoke <device-id>             revoke + rebuild CRL + hubs reload CRL + kill tunnel
#   device-cert.sh unrevoke <device-id>           drop the id from hubs' revoked kick list
#   device-cert.sh revoke-serial <serial>         revoke a specific (e.g. previous) cert
#   device-cert.sh sign   <device-id> <csr-file>   optional: device made its own key
#   device-cert.sh show   <device-id>
#   device-cert.sh list
#
# Output per device: $OUT_DIR/<device-id>/
#   <id>.crt                 device certificate (PEM)
#   <id>.key                 device private key (PEM PKCS#8, unencrypted) — SECRET: deliver over a
#                            protected channel, delete after delivery. Vault does NOT keep it.
#   iot-ca.crt               CA chain (root + intermediate)
#   <id>.<template>          one file per template in configs/client/templates/:
#                            ipsec-params.txt (vendor-neutral settings), mikrotik.rsc, strongswan-swanctl.conf
#   CLIENT_TEMPLATES="ipsec-params.txt"  limits which templates are rendered.
#
# Requires: VAULT_ADDR, VAULT_TOKEN (iot-operator policy), jq, openssl; aws cli for revoke.
# Run on a hardened provisioning host (e.g. EC2 via SSM, encrypted disk), not on laptops.
set -euo pipefail
umask 077
export LC_ALL=C   # [a-z] in regexes must not match uppercase (locale collation)

DOMAIN="${DEVICE_DOMAIN:-iot.example.com}"   # CN = <device-id>.$DOMAIN; one device type, Vault role iot-device
ROLE="iot-device"
HUB_FQDN="${HUB_FQDN:-vpn.iot.example.com}"
TTL="${CERT_TTL:-8760h}"
OUT_DIR="${OUT_DIR:-./out}"
SYNC_FUNCTION="${SYNC_FUNCTION:-iot-session-sync}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="${CLIENT_TEMPLATE_DIR:-$SCRIPT_DIR/../configs/client/templates}"
CLIENT_TEMPLATES="${CLIENT_TEMPLATES:-}"   # empty = all templates in TEMPLATE_DIR

die() { echo "error: $*" >&2; exit 1; }
trim() { local s="${1%$'\r'}"; s="${s#"${s%%[![:space:]]*}"}"; printf '%s' "${s%"${s##*[![:space:]]}"}"; }
valid_id()    { [[ "$1" =~ ^[a-z0-9-]{3,63}$ ]]    || die "bad device id '$1' (a-z 0-9 -, 3..63)"
                [[ "$1" != vpn ]]                    || die "device id 'vpn' is reserved for the hub FQDN"; }
valid_serial(){ [[ "$1" =~ ^[0-9a-f:]{2,128}$ ]]   || die "bad serial '$1'"; }

kv_field() {  # kv_field <device-id> <field>  -> value or empty (missing device => empty)
  { vault kv get -format=json "kv/iot-devices/$1" 2>/dev/null || echo '{}'; } \
    | jq -r ".data.data.$2 // empty"
}

render_client() {  # render_client <device-id> <cn> <dir>  -> <dir>/<id>.<template-name>
  local t name n=0
  [[ -d "$TEMPLATE_DIR" ]] || die "client template dir not found: $TEMPLATE_DIR"
  for t in "$TEMPLATE_DIR"/*; do
    [[ -f "$t" ]] || continue
    name="$(basename "$t")"
    if [[ -n "$CLIENT_TEMPLATES" && " $CLIENT_TEMPLATES " != *" $name "* ]]; then continue; fi
    # values are regex-validated, safe for sed
    sed -e "s|{{DEVICE_ID}}|$1|g" -e "s|{{CN}}|$2|g" -e "s|{{HUB_FQDN}}|$HUB_FQDN|g" "$t" > "$3/$1.$name"
    ! grep -q '{{' "$3/$1.$name" || die "unrendered placeholder in $3/$1.$name"
    n=$((n+1))
  done
  [[ $n -gt 0 ]] || die "no client templates rendered"
}

check_pair() {  # cert and key must match
  local c k
  c=$(openssl x509 -in "$1" -noout -pubkey | openssl sha256)
  k=$(openssl pkey -in "$2" -pubout | openssl sha256)
  [[ "$c" == "$k" ]] || die "certificate and key do not match"
}

# invoke_sync <json-payload> -> prints Lambda result; fails if the function raised
invoke_sync() {
  local resp meta fn_err
  resp=$(mktemp)
  meta=$(aws lambda invoke --function-name "$SYNC_FUNCTION" --cli-binary-format raw-in-base64-out \
    --payload "$1" "$resp") || { rm -f "$resp"; return 1; }
  fn_err=$(jq -r '.FunctionError // empty' <<<"$meta")
  cat "$resp"; echo
  rm -f "$resp"
  [[ -z "$fn_err" ]]
}

# issue_cert <device-id> <mode: new|renew>
issue_cert() {
  local id="$1" mode="$2" cn status prev dir tmp json serial expires
  valid_id "$id"
  cn="$id.$DOMAIN"
  status=$(kv_field "$id" status)
  prev=""
  if [[ "$mode" == new && "$status" == active ]]; then
    die "$id already has an active certificate (use renew or revoke)"
  fi
  [[ "$mode" == renew ]] && prev=$(kv_field "$id" serial)

  dir="$OUT_DIR/$id"
  mkdir -p "$dir"
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' RETURN

  # Vault generates the key pair (type/size from the role) and signs the cert. Key is returned once.
  # PKCS#8 ("BEGIN PRIVATE KEY") is the most widely accepted key format across vendors.
  vault write -format=json "pki_iot/issue/$ROLE" \
    common_name="$cn" ttl="$TTL" exclude_cn_from_sans=false \
    private_key_format="${KEY_FORMAT:-pkcs8}" > "$tmp"

  jq -r '.data.certificate'  "$tmp" > "$dir/$id.crt"
  jq -r '.data.private_key'  "$tmp" > "$dir/$id.key"
  jq -r '.data.ca_chain[]'   "$tmp" > "$dir/iot-ca.crt"
  serial=$(jq -r '.data.serial_number' "$tmp")
  expires=$(jq -r '.data.expiration'   "$tmp")
  rm -f "$tmp"

  check_pair "$dir/$id.crt" "$dir/$id.key"
  render_client "$id" "$cn" "$dir"

  vault kv put "kv/iot-devices/$id" serial="$serial" cn="$cn" status=active \
    issued_at="$(date -u +%FT%TZ)" expires="$expires" prev_serial="$prev" >/dev/null

  echo "$id: cn=$cn serial=$serial -> $dir/"
  if [[ "$status" == revoked ]]; then
    # the CN is still on the hubs' recently-revoked kick list -> new cert would be kicked too
    invoke_sync "{\"action\":\"unrevoke\",\"cn\":\"$cn\"}" >/dev/null \
      || echo "  WARNING: could not remove $cn from hubs' revoked list; run: $0 unrevoke $id" >&2
  fi
  if [[ -n "$prev" ]]; then
    echo "  previous cert $prev is still valid; after the device works on the new one run:"
    echo "  $0 revoke-serial $prev"
  fi
}

cmd="${1:-}"; shift || true

case "$cmd" in
  issue)
    [[ $# -eq 1 ]] || die "usage: issue <device-id>"
    issue_cert "$1" new
    ;;

  bulk)
    [[ $# -eq 1 && -f "$1" ]] || die "usage: bulk <devices.csv>"
    ok=0; fail=0
    while IFS=, read -r id _ || [[ -n "${id:-}" ]]; do   # first column = device id, rest ignored
      id="$(trim "$id")"
      [[ -z "$id" || "$id" == \#* || "$id" == device-id ]] && continue
      # separate process so "set -e" applies inside (it is ignored in if/&& contexts)
      if bash "$0" issue "$id" </dev/null; then ok=$((ok+1)); else fail=$((fail+1)); fi
    done < "$1"
    echo "bulk done: issued=$ok failed=$fail"
    [[ $fail -eq 0 ]]
    ;;

  renew)
    [[ $# -eq 1 ]] || die "usage: renew <device-id>"
    valid_id "$1"
    [[ -n "$(kv_field "$1" cn)" ]] || die "unknown device $1"
    issue_cert "$1" renew
    ;;

  revoke)
    [[ $# -eq 1 ]] || die "usage: revoke <device-id>"
    id="$1"; valid_id "$id"
    serial=$(kv_field "$id" serial); [[ -n "$serial" ]] || die "unknown device $id"
    cn=$(kv_field "$id" cn)
    since=$(date -u +%s)
    # 1. revoke in Vault and rebuild the CRL NOW (auto_rebuild would only do it later)
    vault write pki_iot/revoke serial_number="$serial" >/dev/null
    vault read pki_iot/crl/rotate >/dev/null
    vault kv patch "kv/iot-devices/$id" status=revoked revoked_at="$(date -u +%FT%TZ)" >/dev/null
    # 2. session_sync: every hub re-downloads the CRL (checked: this-update >= since), gets the
    #    revoked list for its 15 s kick scheduler, and drops the live tunnel. Safe to re-run.
    if ! out=$(invoke_sync "{\"action\":\"kill\",\"cn\":\"$cn\",\"since\":$since}"); then
      echo "$out" >&2
      die "certificate revoked, but dropping the live tunnel FAILED on some hub; re-run: $0 revoke $id"
    fi
    echo "$out"
    stale=$(jq -r '(.crl_stale // []) | join(" ")' <<<"$out" 2>/dev/null || true)
    if [[ -n "$stale" ]]; then
      echo "WARNING: CRL not refreshed on: $stale (tunnel dropped; hub kick scheduler blocks reconnects)" >&2
    fi
    echo "revoked $id ($serial)"
    ;;

  unrevoke)
    # Remove the device from the hubs' recently-revoked kick list (Vault revocation stays:
    # the old certificate can never be used again). Normally done automatically by issue.
    [[ $# -eq 1 ]] || die "usage: unrevoke <device-id>"
    id="$1"; valid_id "$id"
    cn=$(kv_field "$id" cn); [[ -n "$cn" ]] || die "unknown device $id"
    invoke_sync "{\"action\":\"unrevoke\",\"cn\":\"$cn\"}" || die "unrevoke failed on some hub; re-run"
    echo "removed $cn from hubs' revoked list"
    ;;

  revoke-serial)
    [[ $# -eq 1 ]] || die "usage: revoke-serial <serial>"
    valid_serial "$1"
    vault write pki_iot/revoke serial_number="$1" >/dev/null
    echo "revoked serial $1"
    ;;

  sign)
    [[ $# -eq 2 ]] || die "usage: sign <device-id> <csr-file>"
    id="$1"; csr="$2"; valid_id "$id"
    [[ "$(kv_field "$id" status)" != active ]] || die "$id already has an active certificate"
    was_revoked=$([[ "$(kv_field "$id" status)" == revoked ]] && echo 1 || true)
    cn="$id.$DOMAIN"; dir="$OUT_DIR/$id"; mkdir -p "$dir"
    out=$(vault write -format=json "pki_iot/sign/$ROLE" csr=@"$csr" common_name="$cn" ttl="$TTL")
    jq -r '.data.certificate' <<<"$out" > "$dir/$id.crt"
    jq -r '.data.ca_chain[]'  <<<"$out" > "$dir/iot-ca.crt"
    vault kv put "kv/iot-devices/$id" serial="$(jq -r .data.serial_number <<<"$out")" \
      cn="$cn" status=active issued_at="$(date -u +%FT%TZ)" expires="$(jq -r .data.expiration <<<"$out")" \
      prev_serial="" >/dev/null
    echo "$id: signed CSR -> $dir/$id.crt (key stays on device)"
    if [[ -n "$was_revoked" ]]; then
      invoke_sync "{\"action\":\"unrevoke\",\"cn\":\"$cn\"}" >/dev/null \
        || echo "  WARNING: could not remove $cn from hubs' revoked list; run: $0 unrevoke $id" >&2
    fi
    ;;

  show)
    [[ $# -eq 1 ]] || die "usage: show <device-id>"
    vault kv get "kv/iot-devices/$1"
    ;;

  list)
    vault kv list -format=json kv/iot-devices | jq -r '.[]'
    ;;

  *)
    awk 'NR>1 && /^#/ {print; next} NR>1 {exit}' "$0"; exit 1 ;;
esac
