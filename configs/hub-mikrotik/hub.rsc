# MikroTik CHR IoT hub — per-instance config (RouterOS 7.x).
# Rendered and imported by hub_lifecycle Lambda via REST after the instance got its slot ENI.
#
# Interfaces:
#   ether1  primary ENI (DHCP)  : ONLY what AWS forces onto the primary ENI: IKE/NAT-T from the NLB
#           (instance targets), NLB health check, AWS Time Sync (link-local). Replies leave via ether1.
#   ether2  slot ENI (fixed IP) : everything else: decrypted device traffic <-> TGW, REST from Lambda,
#           syslog (Palo Alto, SIEM), DNS, CRL download from Vault, licence renewal (internet via TGW).
#           The slot owns the pool: static VPC route {{POOL_CIDR}} -> this ENI (Terraform).
#
# Routing: main table default = ether2 (inner subnet router). Packets whose source is the ether1
# address (IKE and health-check replies) use table "inet" = default via the hub-subnet router.
#
# Placeholders: {{POOL_CIDR}} {{POOL_RANGE}} {{CERT_NAME}} {{SLOT_IP}} {{INNER_PREFIX}} {{INNER_GW}}
#               {{HUB_IP}} {{HUB_GW}} {{DNS_IP}}
#               {{HUB_FQDN}} {{VPC_CIDR}} {{SYSLOG_IP}} {{PA_SYSLOG_IP}} {{CRL_URL}}
# Files uploaded by Lambda just before import: {{CERT_NAME}}.crt, {{CERT_NAME}}.key, iot-ca.crt

/certificate
import file-name=iot-ca.crt passphrase="" trusted=yes
import file-name={{CERT_NAME}}.crt passphrase="" name={{CERT_NAME}}
import file-name={{CERT_NAME}}.key passphrase=""
/certificate settings
set crl-download=yes crl-use=yes crl-store=system
# Explicit CRL source (Vault, DER). session_sync re-adds this entry on revoke to force an
# immediate re-download. Hub must trust Vault's TLS cert (or use an HTTP CRL mirror) — PoC.
/certificate crl
add url="{{CRL_URL}}"

# ---------------------------------------------------------------- slot interface + routing
/interface ethernet
set [find default-name=ether2] comment="slot ENI -> TGW / Palo Alto"
/ip address
add address={{SLOT_IP}}/{{INNER_PREFIX}} interface=ether2 comment="slot IP (PA syslog sender)"

# Order matters (this file is imported over REST on ether1): first the table for ether1 replies,
# then the new default route on ether2, only then the DHCP default route on ether1 is dropped.
/routing table
add name=inet fib
/ip route
add dst-address=0.0.0.0/0 gateway={{HUB_GW}}%ether1 routing-table=inet comment="replies of ether1 (IKE, NLB health)"
add dst-address=169.254.169.123/32 gateway=ether1 routing-table=inet comment="AWS Time Sync (link-local, primary ENI only)"
/routing rule
add src-address={{HUB_IP}}/32 action=lookup-only-in-table table=inet comment="ether1 replies stay on ether1"
/ip route
add dst-address=0.0.0.0/0 gateway={{INNER_GW}}%ether2 comment="device traffic + all hub service traffic -> VPC router -> TGW"
/ip dhcp-client
set [find interface=ether1] add-default-route=no use-peer-dns=no use-peer-ntp=no
/ip dns
set servers={{DNS_IP}}
/system ntp client
set enabled=yes mode=unicast servers=169.254.169.123

# ---------------------------------------------------------------- IPsec
/ip pool
add name=pool-iot ranges={{POOL_RANGE}}

/ip ipsec mode-config
add name=mc-iot address-pool=pool-iot address-prefix-length=32 split-include=10.0.0.0/8 system-dns=no

/ip ipsec profile
add name=iot-ike dh-group=ecp256 enc-algorithm=aes-256 hash-algorithm=sha256 \
    lifetime=12h nat-traversal=yes dpd-interval=15s dpd-maximum-failures=3

/ip ipsec proposal
add name=iot-esp auth-algorithms=sha256 enc-algorithms=aes-256-gcm,aes-256-cbc \
    lifetime=1h pfs-group=none

/ip ipsec policy group
add name=iot

/ip ipsec policy
add group=iot template=yes src-address=10.0.0.0/8 dst-address={{POOL_CIDR}} proposal=iot-esp

/ip ipsec peer
add name=iot-clients exchange-mode=ike2 passive=yes profile=iot-ike send-initial-contact=no

# remote-certificate unset => any client cert chaining to a trusted CA (iot-ca) is accepted.
# remote-id=auto => client's IKE ID must match its certificate (never "ignore": ID spoofing).
/ip ipsec identity
add peer=iot-clients auth-method=digital-signature certificate={{CERT_NAME}} \
    generate-policy=port-strict mode-config=mc-iot policy-template-group=iot \
    my-id=fqdn:{{HUB_FQDN}} remote-id=auto

# ---------------------------------------------------------------- firewall
/ip firewall filter
remove [find]
add chain=input connection-state=established,related action=accept
add chain=input in-interface=ether1 protocol=udp dst-port=500,4500 action=accept comment="IKE/NAT-T"
add chain=input in-interface=ether1 protocol=tcp dst-port=8080 src-address={{VPC_CIDR}} action=accept comment="NLB health check"
add chain=input in-interface=ether2 protocol=tcp dst-port=443 src-address={{VPC_CIDR}} action=accept comment="REST from Lambda (slot IP)"
add chain=input action=drop
add chain=forward connection-state=established,related action=accept
add chain=forward src-address={{POOL_CIDR}} dst-address=10.100.0.0/14 action=drop comment="no IoT east-west (bypasses PA)"
add chain=forward src-address={{POOL_CIDR}} ipsec-policy=in,ipsec out-interface=ether2 action=accept
add chain=forward in-interface=ether2 dst-address={{POOL_CIDR}} action=accept
add chain=forward action=drop
/ip firewall mangle
add chain=forward protocol=tcp tcp-flags=syn action=change-mss new-mss=1360 passthrough=yes

/ip service
set www-ssl address={{VPC_CIDR}}
set www address={{VPC_CIDR}}

# ---------------------------------------------------------------- revoked-device kick (safety net)
# Primary path: on revoke, session_sync forces every hub to re-download the CRL, so a revoked
# device is rejected at IKE_AUTH. If that fails on a hub, this script kicks the device anyway:
# session_sync (on revoke) and hub_lifecycle (at launch) overwrite its source with the current
# recently-revoked list, and the scheduler runs it every 15 s.
/system script
add name=iot-kick-revoked policy=read,write,test source=":local revoked {}"
/system scheduler
add name=iot-kick-revoked interval=15s on-event=iot-kick-revoked policy=read,write,test

# ---------------------------------------------------------------- logging
# 1) Palo Alto User-ID syslog listener: IPsec connect messages (IKE ID + assigned IP)
#    are parsed by a Syslog Parse Profile on PA -> user iot\<id> <-> pool IP.
#    PA accepts only registered senders: the fixed slot IP {{SLOT_IP}}.
# 2) SIEM: same events for history ("who had IP X at 10:32").
/system logging action
add name=pa-userid target=remote remote={{PA_SYSLOG_IP}} remote-port=514 src-address={{SLOT_IP}} \
    bsd-syslog=yes syslog-facility=local5
add name=collector target=remote remote={{SYSLOG_IP}} remote-port=514 src-address={{SLOT_IP}} bsd-syslog=yes syslog-facility=local5
/system logging
add topics=ipsec,info action=pa-userid
add topics=ipsec,info action=collector
add topics=ipsec,error action=collector
# Uploaded cert/key/rsc files are removed by Lambda after import.
