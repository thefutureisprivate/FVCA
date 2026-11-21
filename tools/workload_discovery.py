"""Observe OCI signature locations for an explicitly enabled unsigned exception."""

from http.client import HTTPSConnection
import re
import ssl
import time
from urllib.parse import urlencode, urlsplit

import workload_oci as oci


REGISTRY_HOST = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
ACCEPT = ", ".join((oci.INDEX, oci.MANIFEST, "application/vnd.docker.distribution.manifest.v2+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json"))


def registry_host(host):
    if not isinstance(host, str) or len(host) > 253 or not re.fullmatch(REGISTRY_HOST, host):
        raise ValueError("signature discovery requires a canonical registry DNS name")
    return host


def token_service(value):
    if value is None:
        return None
    if not isinstance(value, dict) or value.keys() != {"url", "service"}:
        raise ValueError("invalid delegated registry token service")
    url = urlsplit(value["url"])
    if (not re.fullmatch(r"/[a-zA-Z0-9/_-]{1,256}", url.path) or url.scheme != "https"
            or url.netloc != registry_host(url.hostname) or url.geturl() != value["url"]
            or url.query or url.fragment or not re.fullmatch(r"[a-zA-Z0-9._-]{1,128}", value["service"])):
        raise ValueError("registry token service must have an exact HTTPS endpoint and audience")
    return url, value["service"]


def request(host, path, headers, context):
    connection = HTTPSConnection(host, timeout=10, context=context)
    deadline = time.monotonic() + 15
    try:
        connection.request("GET", path, headers=headers)
        with connection.getresponse() as response:
            sizes = response.headers.get_all("Content-Length", [])
            if (len(sizes) > 1 or (sizes and not re.fullmatch(r"[0-9]{1,10}", sizes[0]))
                    or (sizes and response.headers.get("Transfer-Encoding"))
                    or response.headers.get("Content-Encoding", "identity") != "identity"):
                raise ValueError("unsupported registry response framing")
            size = int(sizes[0]) if sizes else None
            if size is not None and size > oci.METADATA_LIMIT:
                raise ValueError("registry response exceeds the metadata limit")
            body = bytearray()
            while block := response.read1(65536):
                body.extend(block)
                if time.monotonic() > deadline or len(body) > oci.METADATA_LIMIT:
                    raise ValueError("registry response exceeded its time or size limit")
            if (size is not None and len(body) != size) or time.monotonic() > deadline:
                raise ValueError("incomplete or delayed registry response")
            return response.status, response.headers, bytes(body)
    finally:
        connection.close()


def manifest_unknown(status, headers, body):
    return (status == 404 and headers.get_content_type() == "application/json"
            and [error["code"] for error in oci.parse_json(body)["errors"]] == ["MANIFEST_UNKNOWN"])


def no_referrers_api(status, headers, body):
    if status != 404:
        return False
    if headers.get_content_type() == "application/json":
        codes = [error["code"] for error in oci.parse_json(body)["errors"]]
        return codes in (["MANIFEST_UNKNOWN"], ["UNSUPPORTED"])
    return body in (b"", b"404 page not found\n")


def empty_referrers(headers, body):
    if (headers.get_content_type() != oci.INDEX or "Link" in headers or "OCI-Filters-Applied" in headers
            or oci.manifest_object(body, oci.INDEX)["manifests"] != []):
        raise ValueError("unsigned exception requires an unfiltered and empty OCI referrers list")


def discover(policy, registry_token_service, *, context=None):
    registry, repository = policy["repository"].split("/", 1)
    host = "registry-1.docker.io" if registry == "docker.io" else registry_host(registry)
    context = context or ssl.create_default_context()
    headers = {"Accept": ACCEPT, "Cache-Control": "no-cache"}
    if credential := token_service(registry_token_service):
        endpoint, service = credential
        query = urlencode({"service": service, "scope": f"repository:{repository}:pull"})
        status, token_headers, body = request(endpoint.hostname, f"{endpoint.path}?{query}",
                                              {"Accept": "application/json"}, context)
        if status != 200 or token_headers.get_content_type() != "application/json":
            raise ValueError("registry token service did not authorize the scoped pull")
        result = oci.parse_json(body)
        token = result.get("token", result.get("access_token")) if isinstance(result, dict) else None
        if not isinstance(token, str) or not re.fullmatch(r"[a-zA-Z0-9._~+/=-]{1,8192}", token):
            raise ValueError("registry token service did not return a valid bearer token")
        headers["Authorization"] = f"Bearer {token}"

    def get(path, reference):
        return request(host, f"/v2/{repository}/{path}/{reference}", headers, context)

    subjects = []
    for digest, kind in ((policy["index"], oci.INDEX), (policy["manifest"], oci.MANIFEST)):
        legacy_tag = "sha256-" + oci.digest_hex(digest)
        status, response, body = get("manifests", digest)
        if status != 200 or response.get_content_type() != kind or oci.sha256(body) != digest:
            raise ValueError("registry did not return the exact source index or platform manifest")
        oci.manifest_object(body, kind)

        status, response, body = get("referrers", digest)
        if status == 200:
            empty_referrers(response, body)
        elif not no_referrers_api(status, response, body):
            raise ValueError(f"OCI referrers discovery failed (HTTP {status})")
        referrers = {"status": status, "response": oci.sha256(body)}

        # Check the tag even when the referrers API exists, including mixed deployments.
        status, response, body = get("manifests", legacy_tag)
        if status == 200:
            empty_referrers(response, body)
        elif not manifest_unknown(status, response, body):
            raise ValueError(f"OCI referrers tag could not be ruled out (HTTP {status})")
        tagged_referrers = {"status": status, "response": oci.sha256(body)}

        status, response, body = get("manifests", legacy_tag + ".sig")
        if not manifest_unknown(status, response, body):
            raise ValueError(f"legacy Cosign signature could not be ruled out (HTTP {status})")
        subjects.append({"digest": digest, "referrers_api": referrers, "referrers_tag": tagged_referrers,
                         "cosign_signature_tag": {"status": status, "response": oci.sha256(body)}})

    return {"schema": "fvca-signature-discovery-v1", "repository": policy["repository"], "subjects": subjects}
