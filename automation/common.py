"""Shared clients: RouterOS REST (TLS-pinned), Vault (AWS IAM auth), revoked-list helpers."""
import base64
import hashlib
import hmac
import http.client
import json
import os
import ssl
import time
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

_secrets = boto3.client("secretsmanager")
_secret_cache: dict[str, str] = {}


def secret(secret_id: str) -> str:
    if secret_id not in _secret_cache:
        _secret_cache[secret_id] = _secrets.get_secret_value(SecretId=secret_id)["SecretString"]
    return _secret_cache[secret_id]


# --------------------------------------------------------------------------- RouterOS
class RouterOS:
    """RouterOS 7 REST API client.

    Hubs use a self-signed cert baked into the golden AMI, so instead of CA validation the
    server certificate is pinned by SHA-256 fingerprint (ROS_TLS_FINGERPRINT).
    """

    def __init__(self, host: str, user: str, password: str, fingerprint: str, timeout: int = 15):
        self.host = host
        self.timeout = timeout
        self.fingerprint = fingerprint.replace(":", "").lower()
        self._auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    @classmethod
    def from_env(cls, host: str, timeout: int = 15) -> "RouterOS":
        creds = json.loads(secret(os.environ["ROS_SECRET"]))
        return cls(host, creds["user"], creds["password"], os.environ["ROS_TLS_FINGERPRINT"], timeout)

    def _ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # replaced by fingerprint pinning below
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def call(self, method: str, path: str, body: dict | None = None):
        conn = http.client.HTTPSConnection(self.host, 443, timeout=self.timeout, context=self._ctx())
        try:
            conn.connect()
            peer = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
            if not hmac.compare_digest(peer, self.fingerprint):
                raise ConnectionError(f"{self.host}: TLS fingerprint mismatch")
            data = json.dumps(body).encode() if body is not None else None
            conn.request(method, "/rest" + path, body=data,
                         headers={"Authorization": self._auth, "Content-Type": "application/json"})
            resp = conn.getresponse()
            raw = resp.read()
            if resp.status >= 400:
                raise RuntimeError(f"{self.host} {method} {path}: {resp.status} {raw[:300]!r}")
            return json.loads(raw) if raw else None
        finally:
            conn.close()

    def get(self, path):            return self.call("GET", path)
    def post(self, path, body):     return self.call("POST", path, body)
    def put(self, path, body):      return self.call("PUT", path, body)
    def patch(self, path, body):    return self.call("PATCH", path, body)
    def delete(self, path):         return self.call("DELETE", path)

    def wait_ready(self, timeout_s: int = 240) -> None:
        deadline = time.time() + timeout_s
        while True:
            try:
                self.get("/system/resource")
                return
            except Exception:
                if time.time() > deadline:
                    raise
                time.sleep(10)

    def upload(self, name: str, contents: str) -> None:
        """Create a small text file (certs/keys/rsc). Uses '/file add contents=' (RouterOS 7.x).
        If your version lacks it, switch to S3 presigned URL + POST /tool/fetch."""
        existing = [f for f in self.get("/file") or [] if f.get("name") == name]
        for f in existing:
            self.delete(f"/file/{f['.id']}")
        self.put("/file", {"name": name, "contents": contents})

    def remove_files(self, names: list[str]) -> None:
        for f in self.get("/file") or []:
            if f.get("name") in names:
                self.delete(f"/file/{f['.id']}")


# --------------------------------------------------------------------------- revoked list
# Hubs refresh the CRL only periodically (Vault CRL expiry 48h), so a revoked device could
# reconnect before its hub sees the new CRL. Each hub therefore keeps a short local list of
# recently revoked IKE IDs and a scheduler kicks matching peers every minute.
# Source of truth: SSM parameter (JSON {cn: revoked_at}); entries older than REVOKED_HOLD_H drop.
import re as _re

REVOKED_PARAM = os.environ.get("REVOKED_PARAM", "/iot/revoked-recent")
REVOKED_HOLD_S = int(os.environ.get("REVOKED_HOLD_H", "72")) * 3600  # > CRL expiry (48h)
KICK_SCRIPT = "iot-kick-revoked"
_CN_SAFE = _re.compile(r"^[a-z0-9.-]{3,253}$")
_ssm = boto3.client("ssm")


def load_revoked() -> dict[str, int]:
    try:
        val = _ssm.get_parameter(Name=REVOKED_PARAM)["Parameter"]["Value"]
    except _ssm.exceptions.ParameterNotFound:
        return {}
    now = int(time.time())
    return {k: v for k, v in json.loads(val).items() if now - v < REVOKED_HOLD_S}


def save_revoked(revoked: dict[str, int]) -> None:
    _ssm.put_parameter(Name=REVOKED_PARAM, Value=json.dumps(revoked), Type="String", Overwrite=True)


def kick_script_source(cns: list[str]) -> str:
    """RouterOS script: remove active peers whose IKE ID is in the revoked list."""
    for cn in cns:
        if not _CN_SAFE.match(cn):
            raise ValueError(f"unsafe cn {cn!r}")
    items = ";".join(f'"{cn}";"fqdn:{cn}"' for cn in sorted(cns))
    return (
        f":local revoked {{{items}}}\n"
        ":foreach p in=[/ip ipsec active-peers find] do={\n"
        "  :local pid [/ip ipsec active-peers get $p id]\n"
        "  :if ([:len [:find $revoked $pid]] > 0) do={\n"
        "    /ip ipsec active-peers remove $p\n"
        "    :log warning (\"iot: kicked revoked peer \" . $pid)\n"
        "  }\n"
        "}\n"
    )


def push_revoked(ros: "RouterOS", cns: list[str]) -> None:
    scripts = ros.get(f"/system/script?name={KICK_SCRIPT}") or []
    if not scripts:
        raise RuntimeError(f"{ros.host}: script {KICK_SCRIPT} missing (hub.rsc not applied?)")
    ros.patch(f"/system/script/{scripts[0]['.id']}", {"source": kick_script_source(cns)})


# --------------------------------------------------------------------------- Vault
class Vault:
    """Minimal Vault client using AWS IAM auth (Lambda execution role)."""

    def __init__(self):
        self.addr = os.environ["VAULT_ADDR"].rstrip("/")
        self.role = os.environ["VAULT_ROLE"]
        cafile = os.environ.get("VAULT_CACERT")  # bundled CA if Vault uses private PKI
        self.ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        self.token: str | None = None

    def _http(self, method: str, path: str, payload: dict | None = None) -> dict:
        req = urllib.request.Request(
            f"{self.addr}/v1/{path}",
            data=json.dumps(payload).encode() if payload is not None else None,
            method=method,
            headers={"Content-Type": "application/json", **({"X-Vault-Token": self.token} if self.token else {})},
        )
        with urllib.request.urlopen(req, timeout=10, context=self.ctx) as r:
            return json.loads(r.read() or b"{}")

    def login(self) -> None:
        creds = boto3.session.Session().get_credentials().get_frozen_credentials()
        url = "https://sts.amazonaws.com/"
        body = "Action=GetCallerIdentity&Version=2011-06-15"
        aws_req = AWSRequest(method="POST", url=url, data=body,
                             headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})
        SigV4Auth(creds, "sts", "us-east-1").add_auth(aws_req)
        b64 = lambda s: base64.b64encode(s.encode()).decode()
        res = self._http("POST", "auth/aws/login", {
            "role": self.role,
            "iam_http_request_method": "POST",
            "iam_request_url": b64(url),
            "iam_request_body": b64(body),
            "iam_request_headers": b64(json.dumps({k: [v] for k, v in aws_req.headers.items()})),
        })
        self.token = res["auth"]["client_token"]

    def write(self, path: str, payload: dict) -> dict:
        if not self.token:
            self.login()
        return self._http("POST", path, payload)["data"]

    def read(self, path: str) -> dict:
        if not self.token:
            self.login()
        return self._http("GET", path)["data"]

    def issue_hub_cert(self) -> dict:
        """Returns {'certificate','private_key','ca_chain'(list),'serial_number','expiration'}."""
        return self.write("pki_iot/issue/vpn-hub", {
            "common_name": os.environ["HUB_FQDN"],
            "ttl": os.environ.get("HUB_CERT_TTL", "43800h"),  # 5 years, no rotation
        })
