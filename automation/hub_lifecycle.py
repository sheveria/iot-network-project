"""
hub_lifecycle Lambda — MikroTik CHR hub fleet management with fixed "slot" ENIs. No database.

Slot = pre-created ENI (Terraform) in the hub's AZ "inner" subnet with:
  * a fixed private IP   -> registered once in Palo Alto as a User-ID syslog sender
  * tag iot:pool         -> the /22 client pool this slot owns
  * a static route  pool -> this ENI  (Terraform, never changed at runtime)
  * source/dest check off (forwarding)

  Slot is taken  <=> ENI is attached to an instance
  Slot is free   <=> ENI status "available"

Launch:    attach a free slot ENI of the instance's AZ as device index 1 (attach is atomic:
           an in-use ENI cannot be attached twice), push hub cert + config, CONTINUE.
Terminate: detach the slot ENI (frees the slot immediately), CONTINUE. If the hook never runs,
           EC2 detaches it when the instance terminates; the slot becomes free anyway.

REST address: before hub.rsc the instance answers on its primary IP (ether1, golden AMI); hub.rsc moves
all service traffic to ether2, so afterwards (and for session_sync, via tag iot:slot-ip) the slot IP is used.

Hub certificates are issued once per instance (5 years). No rotation: replacing a hub
(AMI update / ASG instance refresh) gives it a fresh certificate.

Run with reserved concurrency = 1 (serialised launches; attach is atomic anyway).

Env: SLOT_GROUP, HUB_ASG, HUB_FQDN, VPC_CIDR, SYSLOG_IP, PA_SYSLOG_IP, CRL_URL,
     ROS_SECRET, ROS_TLS_FINGERPRINT, VAULT_ADDR, VAULT_ROLE, [VAULT_CACERT],
     [REVOKED_PARAM, REVOKED_HOLD_H, LICENSE_SECRET, LICENSE_LEVEL]
"""
import ipaddress
import json
import logging
import os
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from common import RouterOS, Vault, load_revoked, push_revoked, secret

log = logging.getLogger()
log.setLevel(logging.INFO)

SLOT_GROUP = os.environ.get("SLOT_GROUP", "iot-ipsec-hub")
TEMPLATE = Path(__file__).with_name("hub.rsc")  # copied from configs/hub-mikrotik at build time

ec2 = boto3.client("ec2")
asg = boto3.client("autoscaling")


# ------------------------------------------------------------------ slots
def _slot_from_eni(eni: dict) -> dict:
    tags = {t["Key"]: t["Value"] for t in eni.get("TagSet", [])}
    return {
        "eni": eni["NetworkInterfaceId"],
        "ip": eni["PrivateIpAddress"],
        "pool": tags["iot:pool"],
        "inner_cidr": tags["iot:inner-cidr"],
        "name": tags.get("iot:slot", eni["NetworkInterfaceId"]),
        "status": eni["Status"],
        "instance": (eni.get("Attachment") or {}).get("InstanceId"),
    }


def list_slots(az: str) -> list[dict]:
    res = ec2.describe_network_interfaces(Filters=[
        {"Name": "tag:iot:slot-group", "Values": [SLOT_GROUP]},
        {"Name": "availability-zone", "Values": [az]},
    ])["NetworkInterfaces"]
    return sorted((_slot_from_eni(e) for e in res), key=lambda s: s["name"])


def wait_attached(eni_id: str, timeout_s: int = 60) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        eni = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
        if (eni.get("Attachment") or {}).get("Status") == "attached":
            return
        time.sleep(3)
    raise TimeoutError(f"{eni_id} not attached after {timeout_s}s")


def claim_slot(instance_id: str, az: str) -> dict:
    slots = list_slots(az)
    for s in slots:  # idempotent retry of the same lifecycle event
        if s["instance"] == instance_id:
            return s
    for s in slots:
        if s["status"] != "available":
            continue
        try:
            ec2.attach_network_interface(NetworkInterfaceId=s["eni"], InstanceId=instance_id, DeviceIndex=1)
        except ClientError as e:
            # raced with another attach or ENI changed state -> try the next slot
            log.warning("attach %s failed: %s", s["eni"], e.response["Error"]["Code"])
            continue
        wait_attached(s["eni"])
        return s
    raise RuntimeError(f"no free slot ENI in {az} (add slots: var.slots_per_az)")


def release_slot(instance_id: str, az: str) -> list[str]:
    freed = []
    for s in list_slots(az):
        if s["instance"] != instance_id:
            continue
        eni = ec2.describe_network_interfaces(NetworkInterfaceIds=[s["eni"]])["NetworkInterfaces"][0]
        att = eni.get("Attachment") or {}
        if att.get("AttachmentId"):
            ec2.detach_network_interface(AttachmentId=att["AttachmentId"], Force=True)
            freed.append(s["name"])
    return freed


# ------------------------------------------------------------------ helpers
def instance_info(instance_id: str) -> dict:
    """-> {ip: primary (ether1) private IP, az, gw: VPC router of the hub subnet (base + 1)}"""
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    subnet = ec2.describe_subnets(SubnetIds=[inst["SubnetId"]])["Subnets"][0]["CidrBlock"]
    return {"ip": inst["PrivateIpAddress"], "az": inst["Placement"]["AvailabilityZone"],
            "gw": str(ipaddress.ip_network(subnet).network_address + 1)}


def pool_range(cidr: str) -> str:
    hosts = list(ipaddress.ip_network(cidr).hosts())
    return f"{hosts[0]}-{hosts[-1]}"


def render(slot: dict, cert_name: str, hub: dict) -> str:
    inner = ipaddress.ip_network(slot["inner_cidr"])
    vpc = ipaddress.ip_network(os.environ["VPC_CIDR"])
    values = {
        "HUB_IP": hub["ip"], "HUB_GW": hub["gw"],
        "DNS_IP": str(vpc.network_address + 2),  # Route 53 Resolver, reached over ether2 (VPC-local)
        "POOL_CIDR": slot["pool"], "POOL_RANGE": pool_range(slot["pool"]), "CERT_NAME": cert_name,
        "SLOT_IP": slot["ip"], "INNER_PREFIX": str(inner.prefixlen),
        "INNER_GW": str(inner.network_address + 1),  # VPC router = subnet base + 1
        "HUB_FQDN": os.environ["HUB_FQDN"], "VPC_CIDR": os.environ["VPC_CIDR"],
        "SYSLOG_IP": os.environ["SYSLOG_IP"], "PA_SYSLOG_IP": os.environ["PA_SYSLOG_IP"],
        "CRL_URL": os.environ["CRL_URL"],
    }
    text = TEMPLATE.read_text()
    for k, v in values.items():
        text = text.replace("{{" + k + "}}", v)
    if "{{" in text:
        raise ValueError("unrendered placeholder in hub.rsc")
    return text


def cert_name() -> str:
    return "hub-" + time.strftime("%Y%m%d%H%M", time.gmtime())


def push_cert(ros: RouterOS, cert: dict, name: str) -> None:
    ros.upload(f"{name}.crt", cert["certificate"])
    ros.upload(f"{name}.key", cert["private_key"])
    ros.upload("iot-ca.crt", "\n".join(cert["ca_chain"]))


def wait_ether2(ros: RouterOS, timeout_s: int = 90) -> None:
    """Hot-attached ENI must show up as ether2. If not (no hot-plug), reboot once."""
    def present() -> bool:
        return any(i.get("default-name") == "ether2" for i in ros.get("/interface/ethernet") or [])

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if present():
            return
        time.sleep(5)
    log.warning("ether2 not visible, rebooting CHR once")
    try:
        ros.post("/system/reboot", {})
    except Exception:
        pass  # connection drops during reboot
    time.sleep(30)
    ros.wait_ready()
    if not present():
        raise RuntimeError("slot ENI is attached but ether2 is missing on CHR")


# ------------------------------------------------------------------ provisioning
def connect(hub: dict, slot: dict) -> tuple[RouterOS, bool]:
    """Before hub.rsc the REST API answers on the primary IP (ether1); after it only on the slot IP
    (ether2). -> (client, already_configured)."""
    try:
        ros = RouterOS.from_env(slot["ip"], timeout=5)
        ros.get("/system/resource")
        return RouterOS.from_env(slot["ip"]), True
    except Exception:
        return RouterOS.from_env(hub["ip"]), False


def provision(hub: dict, slot: dict) -> None:
    ros, configured = connect(hub, slot)
    if configured:
        log.info("hub already provisioned (REST answers on the slot IP), skipping config import")
        return
    ros.wait_ready()
    wait_ether2(ros)
    cert = Vault().issue_hub_cert()
    name = cert_name()
    push_cert(ros, cert, name)
    ros.upload("hub.rsc", render(slot, name, hub))
    try:
        ros.post("/import", {"file-name": "hub.rsc"})
    except Exception:
        # hub.rsc moves routing and the REST firewall rule to ether2; the answer on ether1 may be lost
        log.warning("import call on ether1 did not return cleanly, checking on the slot IP", exc_info=True)
    ros = RouterOS.from_env(slot["ip"])  # from now on only the slot IP works
    ros.wait_ready()
    if not ros.get("/ip/pool?name=pool-iot"):
        raise RuntimeError("hub.rsc was not applied (pool-iot missing)")
    ros.remove_files([f"{name}.crt", f"{name}.key", "iot-ca.crt", "hub.rsc"])
    push_revoked(ros, list(load_revoked()))  # new hub starts with the current revoked list

    if os.environ.get("LICENSE_SECRET"):  # CHR clones share system-id; needs internet egress
        lic = json.loads(secret(os.environ["LICENSE_SECRET"]))
        ros.post("/system/license/generate-new-id", {})
        ros.post("/system/license/renew", {"account": lic["account"], "password": lic["password"],
                                           "level": os.environ.get("LICENSE_LEVEL", "p1")})


# ------------------------------------------------------------------ handler
def handler(event, _ctx):
    d = event["detail"]
    instance_id, transition = d["EC2InstanceId"], d["LifecycleTransition"]
    result = "CONTINUE"
    try:
        hub = instance_info(instance_id)
        az = hub["az"]
        if transition == "autoscaling:EC2_INSTANCE_LAUNCHING":
            slot = claim_slot(instance_id, az)
            provision(hub, slot)
            ec2.create_tags(Resources=[instance_id], Tags=[
                {"Key": "iot:pool", "Value": slot["pool"]},
                {"Key": "iot:slot", "Value": slot["name"]},
                {"Key": "iot:slot-ip", "Value": slot["ip"]},  # management address (ether2), used by session_sync
            ])
            log.info(json.dumps({"action": "launch", "instance": instance_id, "slot": slot["name"],
                                 "pool": slot["pool"], "slot_ip": slot["ip"]}))
        elif transition == "autoscaling:EC2_INSTANCE_TERMINATING":
            freed = release_slot(instance_id, az)
            log.info(json.dumps({"action": "terminate", "instance": instance_id, "freed": freed}))
    except Exception:
        log.exception("lifecycle handling failed")
        # Failed launch -> ABANDON: ASG terminates the instance; EC2 detaches the slot ENI.
        result = "ABANDON" if transition.endswith("LAUNCHING") else "CONTINUE"
    finally:
        asg.complete_lifecycle_action(
            LifecycleHookName=d["LifecycleHookName"], AutoScalingGroupName=d["AutoScalingGroupName"],
            LifecycleActionToken=d["LifecycleActionToken"], LifecycleActionResult=result,
            InstanceId=instance_id)
    return {"result": result}
