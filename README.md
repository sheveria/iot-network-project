# IoT IPsec hub on AWS  (MikroTik CHR)

IKEv2 + certificate VPN for ~1000 IoT devices behind NAT. Hubs are MikroTik CHR (RouterOS 7) on EC2.

Traffic path: device → Global Accelerator → NLB (UDP 500/4500) → CHR hub → Transit GW → Palo Alto → services.

- `terraform/` — VPC, NLB, ASG, fixed ENI slots (one /22 pool each)
- `automation/` — Lambdas for hub lifecycle and revocation
- `configs/` — CHR config templates
- `vault/` — PKI and KV setup
- `diagrams/`, `architecture.drawio` — architecture

HA: at least 3 hubs, one per AZ, each able to carry all devices.
