"""Bounded, public-internet-only retrieval for user-selected policy URLs."""

from __future__ import annotations

import asyncio
import codecs
import concurrent.futures
import ipaddress
import re
import socket
import ssl
import threading
from dataclasses import dataclass
from typing import Awaitable, Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

import aiohttp
from aiohttp.abc import AbstractResolver
from bs4 import BeautifulSoup

MAX_RESPONSE_BYTES = 1_000_000
MAX_TEXT_CHARS = 200_000
MAX_REDIRECTS = 4
TOTAL_TIMEOUT_SECONDS = 12
DNS_TIMEOUT_SECONDS = 3
CONNECT_TIMEOUT_SECONDS = 3
READ_TIMEOUT_SECONDS = 4
EXCERPT_CHARS = 1000
MAX_CONCURRENT_POLICY_FETCHES = 8
MAX_CONCURRENT_DNS_LOOKUPS = 4
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
ALLOWED_CONTENT_TYPES = {"text/html", "application/xhtml+xml", "text/plain"}
BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid", ".example")
BLOCKED_HOSTS = {"localhost"}
_POLICY_FETCH_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_POLICY_FETCHES)
_DNS_LOOKUP_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_DNS_LOOKUPS)
_DNS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=MAX_CONCURRENT_DNS_LOOKUPS,
    thread_name_prefix="trusttrace-dns",
)


class PolicyFetchError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class ValidatedURL:
    url: str
    scheme: str
    hostname: str
    port: int


@dataclass(frozen=True)
class ResponseData:
    status: int
    headers: dict[str, str]
    body: bytes


ResolverFunction = Callable[[str, int], Awaitable[list[str]]]
RequestFunction = Callable[[ValidatedURL, list[str]], Awaitable[ResponseData]]


def validate_policy_url(value: str) -> ValidatedURL:
    """Parse a URL and restrict it to ordinary HTTP(S) origins and ports."""
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS policy URLs are supported.")
        if parts.username is not None or parts.password is not None:
            raise ValueError("Policy URLs must not include user information.")
        hostname = parts.hostname
        if not hostname:
            raise ValueError("Policy URL must include a hostname.")
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if not hostname or hostname in BLOCKED_HOSTS or any(hostname.endswith(suffix) for suffix in BLOCKED_HOST_SUFFIXES):
            raise ValueError("Local and reserved hostnames are not allowed.")
        literal = _parse_ip_literal(hostname)
        if literal is None:
            if len(hostname) > 253 or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in hostname.split(".")
            ):
                raise ValueError("Policy URL has an invalid hostname.")
        else:
            # Canonicalize accepted public literals. This also converts legacy
            # IPv4 spellings and IPv4-mapped IPv6 to an ordinary IPv4 address.
            hostname = str(_public_ip(str(literal)))
        port = parts.port
        if port is None:
            port = 443 if scheme == "https" else 80
        expected_port = 443 if scheme == "https" else 80
        if port != expected_port:
            raise ValueError("Only the standard HTTP and HTTPS ports are allowed.")
        # Do not send fragments, credentials, or an empty path to the server.
        path = parts.path or "/"
        normalized = urlunsplit((scheme, _authority(hostname, port, scheme), path, parts.query, ""))
        return ValidatedURL(normalized, scheme, hostname, port)
    except PolicyFetchError:
        raise
    except (UnicodeError, ValueError) as error:
        message = str(error) if str(error) else "Enter a valid HTTP or HTTPS policy URL."
        raise PolicyFetchError(message, 400) from error


def _authority(hostname: str, port: int, scheme: str) -> str:
    try:
        ipaddress.ip_address(hostname)
        host_text = f"[{hostname}]" if ":" in hostname else hostname
    except ValueError:
        host_text = hostname
    default = 443 if scheme == "https" else 80
    return host_text if port == default else f"{host_text}:{port}"


def _public_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise PolicyFetchError("DNS returned an invalid address.", 400) from error
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified:
        raise PolicyFetchError("Policy host resolves to a non-public IP address.", 400)
    return address


def _parse_ip_literal(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        # socket.inet_aton recognizes legacy IPv4 forms such as 127.1,
        # 2130706433, and 0x7f000001 on Windows and Unix.
        try:
            return ipaddress.IPv4Address(socket.inet_aton(hostname))
        except (OSError, ValueError):
            return None


async def resolve_public_addresses(hostname: str, port: int) -> list[str]:
    """Resolve once per hop and reject the whole result if any answer is non-public."""
    literal = _parse_ip_literal(hostname)
    if literal is not None:
        return [str(_public_ip(str(literal)))]

    loop = asyncio.get_running_loop()
    if not _DNS_LOOKUP_SLOTS.acquire(blocking=False):
        raise PolicyFetchError("DNS lookup capacity is temporarily full.", 503)
    try:
        worker = _DNS_EXECUTOR.submit(socket.getaddrinfo, hostname, port, 0, socket.SOCK_STREAM)
        # Release capacity only when the underlying resolver call actually ends.
        # Cancelling the asyncio waiter cannot stop a running system resolver call.
        worker.add_done_callback(lambda _future: _DNS_LOOKUP_SLOTS.release())
        records = await asyncio.wait_for(asyncio.wrap_future(worker, loop=loop), timeout=DNS_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as error:
        if "worker" not in locals():
            _DNS_LOOKUP_SLOTS.release()
        raise PolicyFetchError("Policy hostname lookup timed out.", 504) from error
    except socket.gaierror as error:
        if "worker" not in locals():
            _DNS_LOOKUP_SLOTS.release()
        raise PolicyFetchError("Policy hostname could not be resolved.", 502) from error
    except OSError as error:
        if "worker" not in locals():
            _DNS_LOOKUP_SLOTS.release()
        raise PolicyFetchError("Policy hostname could not be resolved.", 502) from error
    except Exception:
        if "worker" not in locals():
            _DNS_LOOKUP_SLOTS.release()
        raise
    addresses = list(dict.fromkeys(str(_public_ip(record[4][0])) for record in records))
    if not addresses:
        raise PolicyFetchError("Policy hostname did not resolve to an address.", 502)
    return addresses


def _validate_resolved_addresses(addresses: list[str]) -> list[str]:
    """Recheck every resolver result at the request boundary before pinning."""
    checked = list(dict.fromkeys(str(_public_ip(address)) for address in addresses))
    if not checked:
        raise PolicyFetchError("Policy hostname did not resolve to an address.", 502)
    return checked


class PinnedResolver(AbstractResolver):
    """Give aiohttp only the addresses already checked by resolve_public_addresses."""

    def __init__(self, hostname: str, addresses: list[str]) -> None:
        self.hostname = hostname
        self.addresses = addresses

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        if host.lower().rstrip(".") != self.hostname:
            raise OSError("Unexpected hostname during pinned connection.")
        return [
            {
                "hostname": self.hostname,
                "host": address,
                "port": port,
                "family": socket.AF_INET6 if ":" in address else socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for address in self.addresses
        ]

    async def close(self) -> None:
        return None


async def _request_once(
    target: ValidatedURL,
    addresses: list[str],
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> ResponseData:
    resolver = PinnedResolver(target.hostname, addresses)
    connector = aiohttp.TCPConnector(
        resolver=resolver,
        use_dns_cache=False,
        force_close=True,
        ssl=ssl_context if ssl_context is not None else True,
    )
    timeout = aiohttp.ClientTimeout(
        total=TOTAL_TIMEOUT_SECONDS,
        connect=CONNECT_TIMEOUT_SECONDS,
        sock_connect=CONNECT_TIMEOUT_SECONDS,
        sock_read=READ_TIMEOUT_SECONDS,
    )
    try:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            trust_env=False,
            auto_decompress=False,
            headers={
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8",
                "Accept-Encoding": "identity",
                "User-Agent": "TRUSTTRACE-AI-PolicyFetcher/0.2",
            },
        ) as client:
            async with client.get(target.url, allow_redirects=False) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                if response.status in REDIRECT_STATUSES:
                    return ResponseData(response.status, headers, b"")
                content_length = headers.get("content-length")
                if content_length:
                    try:
                        if int(content_length) > MAX_RESPONSE_BYTES:
                            raise PolicyFetchError("Policy response exceeds the 1 MB limit.", 413)
                    except ValueError as error:
                        raise PolicyFetchError("Policy response has an invalid content length.", 502) from error
                data = bytearray()
                async for chunk in response.content.iter_chunked(16_384):
                    data.extend(chunk)
                    if len(data) > MAX_RESPONSE_BYTES:
                        raise PolicyFetchError("Policy response exceeds the 1 MB limit.", 413)
                return ResponseData(response.status, headers, bytes(data))
    except PolicyFetchError:
        raise
    except asyncio.TimeoutError as error:
        raise PolicyFetchError("Policy fetch timed out.", 504) from error
    except (aiohttp.ClientError, OSError, ssl.SSLError) as error:
        raise PolicyFetchError("Policy site could not be fetched safely.", 502) from error


def _extract_text(body: bytes, content_type: str) -> tuple[str, bool]:
    # Header charsets are untrusted. Unknown/invalid labels fall back to UTF-8.
    charset = "utf-8"
    if ";" in content_type:
        for part in content_type.split(";")[1:]:
            name, separator, value = part.strip().partition("=")
            if separator and name.lower() == "charset":
                try:
                    charset = codecs.lookup(value.strip(" \"'" )).name
                except LookupError:
                    pass
    decoded = body.decode(charset, errors="replace")
    if content_type.split(";", 1)[0].strip().lower() == "text/plain":
        text = decoded
    else:
        soup = BeautifulSoup(decoded, "html.parser")
        for node in soup(["script", "style", "noscript", "template", "svg", "canvas", "iframe"]):
            node.decompose()
        for node in soup.find_all(["nav", "header", "footer", "aside", "form"]):
            node.decompose()
        text = soup.get_text("\n", strip=True)
    lines = [" ".join(line.split()) for line in text.splitlines()]
    text = "\n".join(line for line in lines if line)
    truncated = len(text) > MAX_TEXT_CHARS
    return text[:MAX_TEXT_CHARS], truncated


async def _fetch_policy_impl(
    value: str,
    *,
    resolver: ResolverFunction = resolve_public_addresses,
    request_once: RequestFunction = _request_once,
) -> dict[str, object]:
    """Fetch one selected URL, validating and pinning each redirect destination."""
    current = validate_policy_url(value)
    deadline = asyncio.get_running_loop().time() + TOTAL_TIMEOUT_SECONDS
    redirects = 0
    try:
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise PolicyFetchError("Policy fetch timed out.", 504)
            addresses = await asyncio.wait_for(resolver(current.hostname, current.port), timeout=min(remaining, DNS_TIMEOUT_SECONDS + 1))
            addresses = _validate_resolved_addresses(addresses)
            response = await asyncio.wait_for(request_once(current, addresses), timeout=remaining)
            if response.status in REDIRECT_STATUSES:
                location = response.headers.get("location")
                if not location:
                    raise PolicyFetchError("Policy redirect did not include a destination.", 502)
                if redirects >= MAX_REDIRECTS:
                    raise PolicyFetchError("Policy site exceeded the redirect limit.", 502)
                current = validate_policy_url(urljoin(current.url, location))
                redirects += 1
                continue
            if response.status != 200:
                raise PolicyFetchError(f"Policy site returned HTTP {response.status}.", 502)
            content_type = response.headers.get("content-type", "").strip()
            media_type = content_type.split(";", 1)[0].strip().lower()
            if media_type not in ALLOWED_CONTENT_TYPES:
                raise PolicyFetchError("Policy response must be HTML, XHTML, or plain text.", 415)
            encoding = response.headers.get("content-encoding", "identity").lower()
            if encoding not in {"", "identity"}:
                raise PolicyFetchError("Compressed policy responses are not accepted.", 415)
            if len(response.body) > MAX_RESPONSE_BYTES:
                raise PolicyFetchError("Policy response exceeds the 1 MB limit.", 413)
            text, truncated = _extract_text(response.body, content_type)
            excerpts = [
                {"source_url": current.url, "start": offset, "end": min(offset + EXCERPT_CHARS, len(text)), "text": text[offset : offset + EXCERPT_CHARS]}
                for offset in range(0, len(text), EXCERPT_CHARS)
            ]
            return {
                "source_url": current.url,
                "text": text,
                "excerpts": excerpts,
                "truncated": truncated,
                "redirect_count": redirects,
            }
    except asyncio.TimeoutError as error:
        raise PolicyFetchError("Policy fetch timed out.", 504) from error


async def fetch_policy(
    value: str,
    *,
    resolver: ResolverFunction = resolve_public_addresses,
    request_once: RequestFunction = _request_once,
) -> dict[str, object]:
    """Bound total concurrent fetch work; saturated calls fail without waiting."""
    if not _POLICY_FETCH_SLOTS.acquire(blocking=False):
        raise PolicyFetchError("Policy fetch capacity is temporarily full.", 503)
    try:
        return await _fetch_policy_impl(value, resolver=resolver, request_once=request_once)
    finally:
        _POLICY_FETCH_SLOTS.release()
