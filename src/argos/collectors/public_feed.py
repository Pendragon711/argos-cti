"""Optional public feed collector with timeout, size cap, and SSRF guardrails."""

import ipaddress
import socket
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from argos.collectors import CollectedRecord, CollectionResult

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0


def _is_blocked_host(hostname: str) -> bool:
    lowered = hostname.strip().lower().rstrip(".")
    if not lowered or lowered in {"localhost", "localhost.localdomain"} or lowered.endswith(".local"):
        return True
    try:
        ip_obj = ipaddress.ip_address(lowered)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(lowered, None, type=socket.SOCK_STREAM)
        for info in infos:
            addr = info[4][0]
            ip_obj = ipaddress.ip_address(addr.split("%", 1)[0])
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                return True
    except OSError:
        return True
    return False


class PublicFeedCollector:
    requires_network = True

    def __init__(
        self,
        name: str,
        feed_url: str,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self.name = name
        self.feed_url = feed_url
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    def collect(self, target: str | None = None) -> CollectionResult:
        source_name = f"feed:{self.name}"
        parsed = urlparse(self.feed_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return CollectionResult(source=source_name, errors=("invalid_feed_url",))
        if _is_blocked_host(parsed.hostname):
            return CollectionResult(source=source_name, errors=("blocked_private_or_local_host",))

        req = Request(
            self.feed_url,
            headers={"User-Agent": "ARGOS-CTI/0.1 (+https://github.com/local-argos)"},
            method="GET",
        )
        try:
            with urlopen(req, timeout=self.timeout_seconds) as resp:
                raw_bytes = resp.read(self.max_bytes + 1)
                if len(raw_bytes) > self.max_bytes:
                    return CollectionResult(
                        source=source_name,
                        errors=(f"response_exceeds_max_bytes:{self.max_bytes}",),
                    )
                text = raw_bytes.decode("utf-8", errors="replace")
        except (OSError, UnicodeError, ValueError) as exc:
            return CollectionResult(source=source_name, errors=(f"fetch_error:{type(exc).__name__}",))

        records: list[CollectedRecord] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if target and target.lower() not in stripped.lower():
                continue
            records.append(
                CollectedRecord(
                    raw_value=stripped,
                    source=source_name,
                    collection_method="public_feed_get",
                    metadata={"line": line_no, "feed_url": self.feed_url},
                )
            )
        return CollectionResult(source=source_name, records=tuple(records))
