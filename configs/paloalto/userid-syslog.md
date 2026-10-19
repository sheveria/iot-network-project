# Palo Alto: User-ID from MikroTik hub syslog

Goal: Palo Alto maps `iot\<device-id>` ↔ pool IP by itself, from the IPsec syslog of the hubs.
No Lambda and no API calls are involved: automation holds no Palo Alto API key. All IoT devices
are identical, so one security policy covers them; the name is needed for the Traffic log.

Tested: nothing yet. Regexes below are a starting point and MUST be adjusted to real RouterOS
log lines from the PoC (see step 0). Menu paths are for PAN-OS 10.x/11.x; check your version.

## 0. Capture real log lines (PoC)

On a hub, temporarily log to memory and connect/disconnect a test device:

```
/system logging add topics=ipsec,info action=memory
/log print where topics~"ipsec"
```

Find the line(s) that contain BOTH the client IKE ID (`meter-000123.iot.example.com`)
and the assigned pool IP (`10.100.x.y`). Depending on the RouterOS version these may be one
line (e.g. "... peer id: ... acquired 10.100.0.5 address ...") or two separate lines.

- One line with ID + IP → this guide works as is (adjust regex).
- ID and IP in different lines → PA syslog parsing cannot join them. Fallbacks are listed in
  DECISIONS.md, item 1 (RouterOS script that writes one combined `:log info` line, or API login).

## 1. Syslog listener on PA

The listener runs on a dataplane interface reachable from the slot ENIs (`pa_syslog_ip`).

1. Network → Network Profiles → Interface Mgmt: profile `userid-syslog` with **User-ID Syslog
   Listener-UDP** enabled. Permitted IP addresses: the slot IPs (Terraform output
   `slot_syslog_senders`).
2. Attach the profile to the interface that owns `pa_syslog_ip`.
3. Security policy: allow `udp/514` from the slot IPs to `pa_syslog_ip` (zone of the hub VPC
   attachment → zone of the interface).

UDP syslog is unauthenticated. Protection comes from: the fixed sender list (step 3), the
interface mgmt profile permitted IPs, and the hub VPC SG (`iot-ipsec-slot`). Do not open the
listener to other networks.

## 2. Syslog Parse Profile

Device → User Identification → User Mapping → Palo Alto Networks User-ID Agent Setup →
Syslog Filters → Add:

| Field | Value (example, adjust after step 0) |
|---|---|
| Name | `mikrotik-ipsec-login` |
| Type | Regex Identifier |
| Event Regex | `acquired .* address` |
| Username Regex | `([a-z0-9-]{3,63})\.iot\.example\.com` |
| Address Regex | `(10\.100\.\d{1,3}\.\d{1,3})` |

Notes:
- The username group extracts only `<device-id>`. Set the default domain to `iot` (User-ID
  Agent Setup → Server Monitor / or include it via the parse profile) so users are
  `iot\meter-000123`.
- Address regex only matches the pool supernet, so a public peer IP in the same line is ignored.
- Logout: optionally add a second filter for disconnect lines (Event Regex e.g.
  `released .* address`) if your PAN-OS version supports logout via syslog parse profiles.
  Otherwise mappings expire by timeout and are overwritten when an IP is reused.

## 3. Register senders (one-time, fixed list)

Device → User Identification → Server Monitoring → Add, one entry per slot IP:

| Field | Value |
|---|---|
| Name | `iot-slot-<az>-NN` (from Terraform output key) |
| Type | Syslog Sender |
| Network Address | slot IP |
| Connection Type | UDP |
| Filter | `mikrotik-ipsec-login` |
| Default Domain | `iot` |

With 3 AZ × 4 slots that is 12 entries. They change only when `slots_per_az` changes.
For many firewalls: configure in Panorama template; User-ID redistribution shares mappings.

## 4. Timeouts and policy

- User-ID timeout (Device → User Identification → User Mapping → Setup → Enable User
  Identification Timeout): e.g. 720 min. IoT sessions are long; a mapping is refreshed on every
  reconnect, and a reused IP is overwritten by the new login line.
- One security policy for all IoT devices: source zone = hub VPC, source address = pool
  supernet `10.100.0.0/16`, application/service as needed. Source user is not required in
  the policy; it is used for logging and search.
- Traffic log: Source User = `iot\meter-000123`.

## 5. Verify

```
show user ip-user-mapping all type SYSLOG
show user ip-user-mapping ip 10.100.0.5
show user server-monitor state all
debug user-id dump syslog-parse-profile        (or: show user syslog-parse-profile)
```
