"""Parse the S3 destination shared by composition and off-node maintenance."""

from dataclasses import dataclass
import ipaddress
import re


@dataclass(frozen=True)
class Destination:
    endpoint: str
    bucket: str
    prefix: str
    region: str
    repository: str

    @property
    def url(self):
        path = f"{self.bucket}/{self.prefix}" if self.prefix else self.bucket
        return f"s3:https://{self.endpoint}/{path}"


def parse(policy, ca):
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    selected = re.fullmatch(
        rf"FVCA-VM-BACKUP-1\nendpoint=(\[[a-fA-F0-9:]+\]|[0-9.]+):([0-9]{{1,5}})\n"
        rf"bucket=([a-z0-9][a-z0-9-]{{1,61}}[a-z0-9])\nprefix=((?:{label}(?:/{label})*)?)\n"
        r"region=([a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?)\nrepository=([0-9a-f]{64})\n",
        policy.decode("ascii"),
    )
    if selected is None or len(policy) > 2048:
        raise ValueError("invalid VM backup destination policy")
    host, port, bucket, prefix, region, repository = selected.groups()
    address = ipaddress.ip_address(host.strip("[]"))
    if address.is_unspecified or address.is_multicast or not 0 < int(port) <= 65535 or len(prefix) > 160:
        raise ValueError("invalid VM backup endpoint or prefix")
    if not ca.startswith(b"-----BEGIN CERTIFICATE-----") or len(ca) > 65_536:
        raise ValueError("invalid VM backup CA bundle")
    return Destination(f"{host}:{port}", bucket, prefix, region, repository)
