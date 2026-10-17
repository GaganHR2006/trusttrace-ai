import asyncio
import os
import socket
import ssl
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.policy_fetch import (
    MAX_RESPONSE_BYTES,
    PinnedResolver,
    PolicyFetchError,
    ResponseData,
    ValidatedURL,
    _request_once,
    fetch_policy,
    resolve_public_addresses,
    validate_policy_url,
)


PUBLIC_IP = "93.184.216.34"


class FakeNetwork:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def resolve(self, hostname, _port):
        if hostname in {"127.0.0.1", "10.0.0.1", "169.254.169.254", "[::1]", "::1"}:
            return await resolve_public_addresses(hostname, 443)
        return [PUBLIC_IP]

    async def request(self, target, addresses):
        self.calls.append((target.url, addresses))
        value = self.responses[target.url]
        if isinstance(value, Exception):
            raise value
        return value


def html(body, content_type="text/html; charset=utf-8", status=200):
    return ResponseData(status, {"content-type": content_type}, body.encode("utf-8"))


class PolicyURLTests(unittest.TestCase):
    def test_only_http_https_and_default_ports_are_allowed(self):
        self.assertEqual(validate_policy_url("HTTPS://example.com/path#fragment").url, "https://example.com/path")
        for url in (
            "javascript:alert(1)",
            "file:///etc/passwd",
            "ftp://example.com/policy",
            "https://user:pass@example.com/",
            "https://example.com:8443/",
            "https://example.com:0/",
            "not a url",
        ):
            with self.subTest(url=url), self.assertRaises(PolicyFetchError):
                validate_policy_url(url)

    def test_unsafe_ip_literals_are_rejected(self):
        for address in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "[::1]", "[fe80::1]"):
            with self.subTest(address=address), self.assertRaises(PolicyFetchError):
                validate_policy_url(f"http://{address}/")

    def test_legacy_ipv4_forms_and_mapped_ipv6_are_checked_and_canonicalized(self):
        for address in ("127.1", "2130706433", "0x7f000001", "[::ffff:127.0.0.1]"):
            with self.subTest(address=address), self.assertRaises(PolicyFetchError):
                validate_policy_url(f"http://{address}/")
        mapped_public = validate_policy_url("https://[::ffff:93.184.216.34]/policy")
        self.assertEqual(mapped_public.hostname, "93.184.216.34")
        self.assertEqual(mapped_public.url, "https://93.184.216.34/policy")


class PolicyFetchTests(unittest.IsolatedAsyncioTestCase):
    async def test_connector_resolver_pins_only_prevalidated_addresses(self):
        resolver = PinnedResolver("public.example.com", [PUBLIC_IP])
        rows = await resolver.resolve("public.example.com", 443)
        self.assertEqual([row["host"] for row in rows], [PUBLIC_IP])
        with self.assertRaises(OSError):
            await resolver.resolve("other.example.com", 443)

    async def test_https_connector_uses_pinned_ip_hostname_sni_host_and_ignores_proxy(self):
        fixture_dir = Path(__file__).parent / "fixtures"
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(fixture_dir / "policy-test-ca.pem", fixture_dir / "policy-test-key.pem")
        sni_names = []
        server_context.set_servername_callback(lambda _socket, name, _context: sni_names.append(name))
        observed_requests = []

        async def handler(reader, writer):
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                observed_requests.append(request.decode("ascii"))
                body = b"Policy text!"
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                    + body
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=server_context)
        port = server.sockets[0].getsockname()[1]
        client_context = ssl.create_default_context(cafile=str(fixture_dir / "policy-test-ca.pem"))
        resolver_rows = []
        original_resolve = PinnedResolver.resolve

        async def record_resolve(resolver, host, port=0, family=socket.AF_INET):
            rows = await original_resolve(resolver, host, port, family)
            resolver_rows.extend(rows)
            return rows

        try:
            valid_target = ValidatedURL(f"https://policy.test:{port}/privacy", "https", "policy.test", port)
            with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1", "https_proxy": "http://127.0.0.1:1"}), patch.object(
                PinnedResolver, "resolve", record_resolve
            ):
                response = await _request_once(valid_target, ["127.0.0.1"], ssl_context=client_context)
                self.assertEqual(response.body, b"Policy text!")
                self.assertEqual(resolver_rows[0]["host"], "127.0.0.1")
                self.assertIn(f"Host: policy.test:{port}\r\n", observed_requests[0])
                self.assertEqual(sni_names[0], "policy.test")

                wrong_name = ValidatedURL(f"https://wrong.test:{port}/privacy", "https", "wrong.test", port)
                with self.assertRaises(PolicyFetchError):
                    await _request_once(wrong_name, ["127.0.0.1"], ssl_context=client_context)
                self.assertEqual(sni_names[-1], "wrong.test")
        finally:
            server.close()
            await server.wait_closed()

    async def test_dns_lookup_capacity_is_bounded_even_if_system_lookup_is_slow(self):
        release = threading.Event()
        count_lock = threading.Lock()
        started = 0

        def slow_getaddrinfo(_hostname, port, _family, _type):
            nonlocal started
            with count_lock:
                started += 1
            release.wait(timeout=2)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port))]

        with patch("backend.app.policy_fetch.socket.getaddrinfo", side_effect=slow_getaddrinfo):
            tasks = [asyncio.create_task(resolve_public_addresses(f"dns{index}.example", 443)) for index in range(4)]
            try:
                for _ in range(100):
                    with count_lock:
                        if started == 4:
                            break
                    await asyncio.sleep(0.01)
                self.assertEqual(started, 4)
                with self.assertRaises(PolicyFetchError) as caught:
                    await resolve_public_addresses("fifth.example", 443)
                self.assertEqual(caught.exception.status_code, 503)
            finally:
                release.set()
                await asyncio.gather(*tasks)

    async def test_total_policy_fetch_concurrency_is_bounded(self):
        from backend.app.policy_fetch import MAX_CONCURRENT_POLICY_FETCHES

        entered = 0
        entered_lock = asyncio.Lock()
        release = asyncio.Event()

        async def resolver(_hostname, _port):
            return [PUBLIC_IP]

        async def waiting_request(_target, _addresses):
            nonlocal entered
            async with entered_lock:
                entered += 1
            await release.wait()
            return ResponseData(200, {"content-type": "text/plain"}, b"Policy")

        tasks = [
            asyncio.create_task(
                fetch_policy(
                    f"https://site{index}.example.com/policy",
                    resolver=resolver,
                    request_once=waiting_request,
                )
            )
            for index in range(MAX_CONCURRENT_POLICY_FETCHES)
        ]
        try:
            for _ in range(100):
                if entered == MAX_CONCURRENT_POLICY_FETCHES:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(entered, MAX_CONCURRENT_POLICY_FETCHES)
            with self.assertRaises(PolicyFetchError) as caught:
                await fetch_policy("https://overflow.example/policy", resolver=resolver, request_once=waiting_request)
            self.assertEqual(caught.exception.status_code, 503)
        finally:
            release.set()
            await asyncio.gather(*tasks)

    async def test_valid_html_returns_exact_text_and_source_offsets(self):
        url = "https://public.example.com/policy"
        network = FakeNetwork({url: html("<html><nav>Menu</nav><main><h1>Privacy</h1><p>We collect data.</p><script>ignore()</script></main></html>")})
        result = await fetch_policy(url, resolver=network.resolve, request_once=network.request)
        self.assertEqual(result["source_url"], url)
        self.assertEqual(result["text"], "Privacy\nWe collect data.")
        self.assertEqual(result["excerpts"], [{"source_url": url, "start": 0, "end": 24, "text": "Privacy\nWe collect data."}])
        self.assertEqual(network.calls, [(url, [PUBLIC_IP])])

    async def test_every_excerpt_matches_returned_text_with_non_bmp_characters(self):
        url = "https://public.example.com/unicode"
        source_text = "a" * 998 + "😀𝄞" + "b" * 1300 + "🛡️"
        network = FakeNetwork({url: ResponseData(200, {"content-type": "text/plain; charset=utf-8"}, source_text.encode("utf-8"))})
        result = await fetch_policy(url, resolver=network.resolve, request_once=network.request)
        self.assertEqual(result["text"], source_text)
        for excerpt in result["excerpts"]:
            with self.subTest(start=excerpt["start"], end=excerpt["end"]):
                self.assertEqual(excerpt["text"], result["text"][excerpt["start"] : excerpt["end"]])
                self.assertEqual(excerpt["end"] - excerpt["start"], len(excerpt["text"]))

    async def test_malformed_html_is_tolerated_and_nontext_elements_removed(self):
        url = "https://public.example.com/policy"
        network = FakeNetwork({url: html("<html><body><h1>Privacy<p>Keep this<script>drop me")})
        result = await fetch_policy(url, resolver=network.resolve, request_once=network.request)
        self.assertIn("Privacy", result["text"])
        self.assertIn("Keep this", result["text"])
        self.assertNotIn("drop me", result["text"])

    async def test_missing_policy_and_unsupported_content_type_fail(self):
        url = "https://public.example.com/policy"
        for response, status in ((html("not found", status=404), 502), (html("<pdf>", "application/pdf"), 415)):
            with self.subTest(status=status):
                network = FakeNetwork({url: response})
                with self.assertRaises(PolicyFetchError) as caught:
                    await fetch_policy(url, resolver=network.resolve, request_once=network.request)
                self.assertEqual(caught.exception.status_code, status)

    async def test_redirect_is_resolved_and_validated_before_second_request(self):
        source = "https://public.example.com/start"
        destination = "https://public.example.com/privacy"
        network = FakeNetwork({
            source: ResponseData(302, {"location": "/privacy"}, b""),
            destination: html("<p>Policy text</p>"),
        })
        result = await fetch_policy(source, resolver=network.resolve, request_once=network.request)
        self.assertEqual(result["source_url"], destination)
        self.assertEqual(result["redirect_count"], 1)
        self.assertEqual([call[0] for call in network.calls], [source, destination])

    async def test_redirect_to_private_or_invalid_destination_is_blocked(self):
        source = "https://public.example.com/start"
        for location in ("http://127.0.0.1/metadata", "http://169.254.169.254/latest/meta-data", "file:///etc/passwd"):
            network = FakeNetwork({source: ResponseData(302, {"location": location}, b"")})
            with self.subTest(location=location), self.assertRaises(PolicyFetchError):
                await fetch_policy(source, resolver=network.resolve, request_once=network.request)
            self.assertEqual(len(network.calls), 1)

    async def test_redirect_revalidates_second_host_dns_answers(self):
        source = "https://public.example.com/start"
        destination = "https://next.example.net/privacy"
        responses = {source: ResponseData(302, {"location": destination}, b"")}
        network = FakeNetwork(responses)
        calls = []

        async def redirect_resolver(host, port):
            calls.append(host)
            if host == "next.example.net":
                return [PUBLIC_IP, "10.0.0.7"]
            return [PUBLIC_IP]

        with self.assertRaises(PolicyFetchError):
            await fetch_policy(source, resolver=redirect_resolver, request_once=network.request)
        self.assertEqual(calls, ["public.example.com", "next.example.net"])
        self.assertEqual([call[0] for call in network.calls], [source])

    async def test_dns_answer_is_resolved_once_then_pinned_for_the_request(self):
        url = "https://rebinding.example.com/policy"
        resolver_calls = 0
        request_addresses = []

        async def changing_resolver(_host, _port):
            nonlocal resolver_calls
            resolver_calls += 1
            return [PUBLIC_IP] if resolver_calls == 1 else ["127.0.0.1"]

        async def record_request(_target, addresses):
            request_addresses.extend(addresses)
            return html("<p>Policy</p>")

        result = await fetch_policy(url, resolver=changing_resolver, request_once=record_request)
        self.assertEqual(result["text"], "Policy")
        self.assertEqual(resolver_calls, 1)
        self.assertEqual(request_addresses, [PUBLIC_IP])

    async def test_redirect_limit_is_enforced(self):
        start = "https://public.example.com/0"
        routes = {}
        for index in range(5):
            routes[f"https://public.example.com/{index}"] = ResponseData(302, {"location": f"/{index + 1}"}, b"")
        network = FakeNetwork(routes)
        with self.assertRaises(PolicyFetchError) as caught:
            await fetch_policy(start, resolver=network.resolve, request_once=network.request)
        self.assertEqual(caught.exception.status_code, 502)
        self.assertEqual(len(network.calls), 5)

    async def test_timeout_and_oversized_response_are_rejected(self):
        url = "https://public.example.com/policy"
        network = FakeNetwork({url: asyncio.TimeoutError()})
        with self.assertRaises(PolicyFetchError) as caught:
            await fetch_policy(url, resolver=network.resolve, request_once=network.request)
        self.assertEqual(caught.exception.status_code, 504)

        network = FakeNetwork({url: ResponseData(200, {"content-type": "text/plain"}, b"x" * (MAX_RESPONSE_BYTES + 1))})
        with self.assertRaises(PolicyFetchError) as caught:
            await fetch_policy(url, resolver=network.resolve, request_once=network.request)
        self.assertEqual(caught.exception.status_code, 413)

    async def test_bad_dns_answer_is_rejected(self):
        async def mixed_resolver(_host, _port):
            return [PUBLIC_IP, "192.168.1.2"]

        with self.assertRaises(PolicyFetchError):
            await fetch_policy("https://public.example.com/policy", resolver=mixed_resolver)


if __name__ == "__main__":
    unittest.main()
