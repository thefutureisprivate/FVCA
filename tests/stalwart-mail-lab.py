#!/usr/bin/env python3
"""Prepare a synthetic mailbox with the pinned Stalwart image offline."""

import argparse
import base64
from email.message import EmailMessage
from email.policy import SMTP
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time


POLICY = Path(__file__).resolve().parents[1] / "policy/workloads/stalwart-v1.1.1.json"
ADDRESS = "recovery@fvca.test"
HTTP = "http://127.0.0.1:8080"
SERVER = "mail.fvca.test"


def podman(*arguments, **options):
    return subprocess.run(["podman", *arguments], capture_output=True, timeout=60, **options)


def require(result, operation):
    if result.returncode != 0:
        raise RuntimeError(f"{operation} failed with exit status {result.returncode}")
    return result.stdout


def curl_config(url, *, payload=None, **options):
    options["url"] = url
    if payload is not None:
        options["header"] = "Content-Type: application/json"
        options["data-binary"] = json.dumps(payload)
    return "".join(f"{name.replace('_', '-')} = {json.dumps(value)}\n" for name, value in options.items()).encode()


def curl(container, config):
    return podman("exec", "--interactive", container, "/usr/bin/curl", "--silent", "--show-error", "--fail",
                  "--max-time", "10", "--config", "-", input=config)


def jmap(container, credential, method, arguments):
    payload = {"using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
               "methodCalls": [[method, arguments, "lab"]]}
    output = require(curl(container, curl_config(f"{HTTP}/jmap/", user=credential, payload=payload)), method)
    result, fields, operation = json.loads(output)["methodResponses"][0]
    if result != method or operation != "lab" or any(fields.get(key) for key in ("notCreated", "notUpdated", "notDestroyed")):
        raise RuntimeError(f"{method} refused the lab configuration")
    return fields


def ready(container):
    for _ in range(24):
        if curl(container, curl_config(f"{HTTP}/healthz/live")).returncode == 0:
            return
        time.sleep(0.5)
    raise RuntimeError("Stalwart did not reach HTTP health readiness")


def configure(container, admin, password):
    listeners = jmap(container, admin, "x:NetworkListener/get", {})["list"]
    jmap(container, admin, "x:NetworkListener/set", {
        "destroy": [listener["id"] for listener in listeners],
        "create": {
            name: {"name": f"fvca-lab-{name}", "protocol": name, "useTls": name != "http", "implicitTls": name != "http",
                   "bind": {f"127.0.0.1:{port}": True}}
            for name, port in (("http", 8080), ("smtp", 2525), ("imap", 1993))
        },
    })
    domain = jmap(container, admin, "x:Domain/set", {"create": {"test": {
        "name": "fvca.test", "certificateManagement": {"@type": "Manual"},
        "dnsManagement": {"@type": "Manual"}, "dkimManagement": {"@type": "Manual"},
    }}})["created"]["test"]["id"]
    jmap(container, admin, "x:SystemSettings/set", {
        "update": {"singleton": {"defaultHostname": SERVER, "defaultDomainId": domain}},
    })
    jmap(container, admin, "x:Certificate/set", {"create": {"loopback": {
        "certificate": {"@type": "File", "filePath": "/etc/stalwart/lab.pem"},
        "privateKey": {"@type": "File", "filePath": "/etc/stalwart/lab.key"},
    }}})
    jmap(container, admin, "x:Account/set", {"create": {"mailbox": {
        "@type": "User", "name": "recovery", "domainId": domain, "roles": {"@type": "User"},
        "credentials": {"0": {"@type": "Password", "secret": password}},
    }}})


def mail_fixture(config):
    message = EmailMessage(policy=SMTP)
    message["From"] = ADDRESS
    message["To"] = ADDRESS
    message["Subject"] = "FVCA restored mail fixture"
    token = secrets.token_hex(16)
    message["Message-ID"] = f"<{token}@fvca.test>"
    message.set_content(f"FVCA mailbox verification {token}")
    (config / "lab-message.eml").write_bytes(message.as_bytes())
    return token.encode()


def certificate(config):
    def openssl(*args, **options):
        return subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=20, **options).stdout

    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-days", "2", "-subj", f"/CN={SERVER}", "-addext", f"subjectAltName=DNS:{SERVER}",
            "-keyout", str(config / "lab.key"), "-out", str(config / "lab.pem"))
    key = openssl("x509", "-in", str(config / "lab.pem"), "-pubkey", "-noout")
    der = openssl("pkey", "-pubin", "-outform", "DER", input=key)
    return "sha256//" + base64.b64encode(hashlib.sha256(der).digest()).decode()


def provision(output):
    source = json.loads(POLICY.read_text())
    image = f"{source['repository']}@{source['manifest']}"
    actual = json.loads(require(podman("image", "inspect", image), "pinned Stalwart image lookup"))[0]
    if image not in actual["RepoDigests"] or (actual["Architecture"], actual["Os"]) != ("amd64", "linux"):
        raise RuntimeError("the locally staged image does not match the pinned workload")
    output.mkdir(mode=0o700)
    config, data = output / "config", output / "data"
    config.mkdir()
    data.mkdir()
    (config / "config.json").write_text(json.dumps({"@type": "Sqlite", "path": "/var/lib/stalwart/stalwart.db",
                                                    "poolWorkers": 2, "poolMaxConnections": 2}) + "\n")
    pin = certificate(config)
    token = mail_fixture(config)
    require(podman("unshare", "chown", "-R", f"{source['uid']}:{source['gid']}", str(config), str(data)),
            "lab store ownership")
    # The upstream executable retains this file capability. The appliance
    # removes file capabilities during the verified EROFS derivation.
    options = ["run", "--detach", "--pull=never", "--network=none", "--read-only", "--cap-drop=all",
               "--cap-add=NET_BIND_SERVICE",
               "--security-opt=no-new-privileges", "--volume", f"{config}:/etc/stalwart:Z",
               "--volume", f"{data}:/var/lib/stalwart:Z"]
    admin = f"lab-recovery:{secrets.token_urlsafe(24)}"
    password = secrets.token_urlsafe(24)
    container = require(podman(*options, "--env", "STALWART_RECOVERY_MODE=1", "--env", "STALWART_RECOVERY_ADMIN",
                               actual["Id"], env={**os.environ, "STALWART_RECOVERY_ADMIN": admin}), "recovery startup").decode().strip()
    try:
        ready(container)
        configure(container, admin, password)
    finally:
        stop(container, output / "configuration.log")

    runtime_env = {name: value for name, value in os.environ.items() if not name.startswith("STALWART_")}
    container = require(podman(*options, actual["Id"], env=runtime_env), "configured startup").decode().strip()
    try:
        ready(container)
        tls = {"user": f"{ADDRESS}:{password}", "cacert": "/etc/stalwart/lab.pem", "pinnedpubkey": pin}
        delivery = curl_config(f"smtps://{SERVER}:2525/{SERVER}", resolve=f"{SERVER}:2525:127.0.0.1", **tls,
                               mail_from=ADDRESS, mail_rcpt=ADDRESS, upload_file="/etc/stalwart/lab-message.eml")
        require(curl(container, delivery), "authenticated loopback SMTP delivery")
        request = curl_config(f"imaps://{SERVER}:1993/INBOX;UID=1", resolve=f"{SERVER}:1993:127.0.0.1", **tls)
        for _ in range(20):
            fetched = curl(container, request)
            if fetched.returncode == 0 and b"FVCA mailbox verification " + token in fetched.stdout:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("the authenticated IMAP session did not retrieve the delivered message")
        (output / "imap.curl").write_bytes(request)
        (output / "mail.eml").write_bytes(fetched.stdout)
        print("FVCA_STALWART_SMTP_IMAP_VERIFIED")
    finally:
        stop(container, output / "configured.log")
    require(podman("unshare", "rm", "--", str(config / "lab-message.eml")), "remove the synthetic SMTP input")


def stop(container, log):
    try:
        require(podman("stop", "--time", "15", container), "orderly Stalwart stop")
        records = podman("logs", container)
        log.write_bytes(require(records, "Stalwart logs") + records.stderr)
    finally:
        require(podman("rm", container), "remove the stopped lab container")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="a new private directory for synthetic mail and configuration")
    args = parser.parse_args()
    os.umask(0o077)
    provision(args.output.absolute())


if __name__ == "__main__":
    main()
