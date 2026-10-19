"""
session_sync Lambda — drops a revoked device and makes every hub use the new CRL immediately.
No schedule: invoked only by vault/device-cert.sh.

  {"action": "kill", "cn": "<device-cn>", "since": <unix ts before revoke>}
      device-cert.sh has already revoked the cert in Vault and called pki_iot/crl/rotate, so
      Vault's CRL already contains the serial. For every hub (in parallel):
        1. push the recently-revoked list into script iot-kick-revoked (safety net, runs every 15 s)
        2. force the hub to re-download the CRL now and check its this-update >= since
        3. remove the device's live tunnel(s)
      After step 2 a reconnect is rejected at IKE_AUTH; step 1 covers hubs where step 2 failed.

  {"action": "unrevoke", "cn": "<device-cn>"}
      remove the CN from the recently-revoked list on SSM and all hubs (e.g. a new certificate was
      issued for the same device id). Vault revocation itself is permanent; the old serial stays
      in the CRL.

CRL refresh modes (CRL_REFRESH_MODE):
  readd   delete + re-add the /certificate crl entry with CRL_URL -> RouterOS downloads it again
  import  Lambda downloads the PEM CRL from Vault and imports it via /certificate import
  auto    readd, and if the CRL is still not fresh after CRL_WAIT_S, import (default)
Which of these works on your RouterOS version must be confirmed in the PoC.

Env: HUB_ASG, DEVICE_DOMAIN, ROS_SECRET, ROS_TLS_FINGERPRINT, CRL_URL,
     [CRL_PEM_URL, CRL_REFRESH_MODE, CRL_WAIT_S, CRL_SKEW_S, VAULT_CACERT, ROUTER_TZ_OFFSET_S,
      REVOKED_PARAM, REVOKED_HOLD_H]
"""
import json
import logging
import os
import re
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import boto3

from common import RouterOS, load_revoked, push_revoked, save_revoked

log = logging.getLogger()
log.setLevel(logging.INFO)

HUB_ASG = os.environ.get("HUB_ASG", "iot-ipsec-hub")
DEVICE_DOMAIN = os.environ.get("DEVICE_DOMAIN", "iot.example.com")
CRL_URL = os.environ.get("CRL_URL", "")
CRL_PEM_URL = os.environ.get("CRL_PEM_URL", CRL_URL.rstrip("/") + "/pem" if CRL_URL else "")
CRL_MODE = os.environ.get("CRL_REFRESH_MODE", "auto")
CRL_WAIT_S = int(os.environ.get("CRL_WAIT_S", "20"))
CRL_SKEW_S = int(os.environ.get("CRL_SKEW_S", "5"))           # clock skew Vault vs provisioning host
TZ_OFFSET_S = int(os.environ.get("ROUTER_TZ_OFFSET_S", "0"))  # CHR clock zone vs UTC (default UTC)
ID_RE = re.compile(r"^(?:fqdn:)?([a-z0-9-]{3,63})\." + re.escape(DEVICE_DOMAIN) + r"$")

ec2 = boto3.client("ec2")


def parse_id(raw: str) -> str | None:
    m = ID_RE.match((raw or "").strip().lower())
    return m.group(1) if m else None


def hubs() -> list[dict]:
    res = ec2.describe_instances(Filters=[
        {"Name": "tag:aws:autoscaling:groupName", "Values": [HUB_ASG]},
        {"Name": "instance-state-name", "Values": ["running"]},
        {"Name": "tag-key", "Values": ["iot:pool"]},  # set only after successful provisioning
    ])
    out = []
    for r in res["Reservations"]:
        for i in r["Instances"]:
            tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
            if "iot:slot-ip" in tags:  # REST answers only on the slot IP (ether2)
                out.append({"id": i["InstanceId"], "ip": tags["iot:slot-ip"]})
    return out


# ------------------------------------------------------------------ CRL refresh
_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def parse_ros_time(value: str) -> int | None:
    """RouterOS date formats: '2026-10-17 14:10:05' (7.10+) or 'oct/17/2026 14:10:05' (older)."""
    v = (value or "").strip().lower()
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[ t](\d{2}):(\d{2}):(\d{2})", v)
    if m:
        y, mo, d, h, mi, s = map(int, m.groups())
    else:
        m = re.match(r"^([a-z]{3})/(\d{2})/(\d{4}) (\d{2}):(\d{2}):(\d{2})", v)
        if not m or m.group(1) not in _MONTHS:
            return None
        mo = _MONTHS[m.group(1)]
        d, y, h, mi, s = int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6))
    return int(datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc).timestamp()) - TZ_OFFSET_S


def newest_crl_update(ros: RouterOS) -> int | None:
    """Newest this-update over all CRLs on the hub (we have a single issuing CA)."""
    times = [parse_ros_time(c.get("this-update", "")) for c in ros.get("/certificate/crl") or []]
    times = [t for t in times if t]
    return max(times) if times else None


def _wait_fresh(ros: RouterOS, since: int) -> bool:
    deadline = time.time() + CRL_WAIT_S
    while True:
        t = newest_crl_update(ros)
        if t is not None and t >= since - CRL_SKEW_S:
            return True
        if time.time() >= deadline:
            return False
        time.sleep(2)


def _readd(ros: RouterOS) -> None:
    for c in ros.get("/certificate/crl") or []:
        if c.get("url") == CRL_URL:
            ros.delete(f"/certificate/crl/{c['.id']}")
    ros.put("/certificate/crl", {"url": CRL_URL})


def _fetch_pem_crl() -> str:
    cafile = os.environ.get("VAULT_CACERT")
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    with urllib.request.urlopen(CRL_PEM_URL, timeout=10, context=ctx) as r:
        pem = r.read().decode()
    if "BEGIN X509 CRL" not in pem:
        raise RuntimeError("Vault did not return a PEM CRL")
    return pem


def _import(ros: RouterOS, pem: str) -> None:
    ros.upload("iot-crl.pem", pem)
    try:
        ros.post("/certificate/import", {"file-name": "iot-crl.pem", "passphrase": ""})
    finally:
        ros.remove_files(["iot-crl.pem"])


def refresh_crl(ros: RouterOS, since: int, pem_cache: dict) -> str:
    """-> 'fresh' | 'stale'. Raises on REST errors."""
    if CRL_MODE in ("readd", "auto"):
        _readd(ros)
        if _wait_fresh(ros, since):
            return "fresh"
        if CRL_MODE == "readd":
            return "stale"
    if "pem" not in pem_cache:
        pem_cache["pem"] = _fetch_pem_crl()
    _import(ros, pem_cache["pem"])
    return "fresh" if _wait_fresh(ros, since) else "stale"


# ------------------------------------------------------------------ actions
def kill_on_hub(ros: RouterOS, ident: str) -> int:
    n = 0
    for p in ros.get("/ip/ipsec/active-peers") or []:
        if parse_id(p.get("id", "")) == ident:
            ros.post("/ip/ipsec/active-peers/remove", {".id": p[".id"]})
            n += 1
    return n


def _per_hub(h: dict, ident: str, revoked: list[str], since: int, pem_cache: dict) -> dict:
    ros = RouterOS.from_env(h["ip"])
    out = {"hub": h["id"], "list": "error", "crl": "error", "killed": 0}
    push_revoked(ros, revoked)                     # 1. safety net first
    out["list"] = "ok"
    try:
        out["crl"] = refresh_crl(ros, since, pem_cache)   # 2. new CRL before kicking
    except Exception:
        log.exception("CRL refresh failed on %s", h["id"])
    out["killed"] = kill_on_hub(ros, ident)        # 3. drop live tunnel
    return out


def _cn(raw: str) -> tuple[str, str]:
    ident = parse_id(raw)
    if not ident:
        raise ValueError("bad cn")
    return f"{ident}.{DEVICE_DOMAIN}", ident


def _fanout(fn, hs: list[dict]) -> tuple[list[dict], list[str]]:
    results, failed = [], []
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = {h["id"]: pool.submit(fn, h) for h in hs}
    for hid, f in futures.items():
        try:
            results.append(f.result())
        except Exception:
            log.exception("hub %s failed", hid)
            failed.append(hid)
    return results, failed


def kill(raw_cn: str, since: int | None = None) -> dict:
    cn, ident = _cn(raw_cn)
    since = int(since or time.time())
    revoked = load_revoked()
    revoked[cn] = since
    save_revoked(revoked)

    pem_cache: dict = {}
    results, failed = _fanout(lambda h: _per_hub(h, ident, list(revoked), since, pem_cache), hubs())
    crl_stale = [r["hub"] for r in results if r["crl"] != "fresh"]
    log.info(json.dumps({"action": "kill", "cn": cn, "since": since, "hubs": results,
                         "failed": failed, "crl_stale": crl_stale}))
    if failed:  # hub unreachable: tunnel may still be up. device-cert.sh revoke is safe to re-run
        raise RuntimeError(f"kill incomplete on hubs {failed}")
    return {"cn": cn, "hubs": results, "crl_stale": crl_stale}


def unrevoke(raw_cn: str) -> dict:
    cn, _ = _cn(raw_cn)
    revoked = load_revoked()
    existed = revoked.pop(cn, None) is not None
    save_revoked(revoked)
    results, failed = _fanout(
        lambda h: (push_revoked(RouterOS.from_env(h["ip"]), list(revoked)), {"hub": h["id"]})[1], hubs())
    log.info(json.dumps({"action": "unrevoke", "cn": cn, "was_listed": existed, "failed": failed}))
    if failed:
        raise RuntimeError(f"unrevoke incomplete on hubs {failed}")
    return {"cn": cn, "was_listed": existed, "hubs": [r["hub"] for r in results]}


def handler(event, _ctx):
    if not isinstance(event, dict) or not event.get("cn"):
        raise ValueError('expected {"action": "kill"|"unrevoke", "cn": "..."}')
    if event.get("action") == "kill":
        return kill(event["cn"], event.get("since"))
    if event.get("action") == "unrevoke":
        return unrevoke(event["cn"])
    raise ValueError(f"unknown action {event.get('action')!r}")
