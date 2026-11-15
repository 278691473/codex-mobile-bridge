import base64
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from bridge.features.network import zcode_relay as relay


THREAD = "11111111-1111-4111-8111-111111111111"
PHONE_ORIGIN = "http://127.0.0.7:43123"


def request_start(request_id=THREAD, method="GET", path="/api/auth", length=0, headers=None):
    return {
        "zcode_type": "platform-request",
        "requestId": request_id,
        "bridgeHttp": 1,
        "kind": "start",
        "method": method,
        "path": path,
        "headers": headers or {
            "Origin": PHONE_ORIGIN,
            "Cookie": "bridge=phone",
            "X-CSRF-Token": "csrf-from-phone",
        },
        "length": length,
    }


def request_chunk(request_id, seq, data):
    return {
        "zcode_type": "platform-request",
        "requestId": request_id,
        "bridgeHttp": 1,
        "kind": "chunk",
        "seq": seq,
        "data": base64.b64encode(data).decode("ascii"),
    }


def request_end(request_id, seq):
    return {
        "zcode_type": "platform-request",
        "requestId": request_id,
        "bridgeHttp": 1,
        "kind": "end",
        "seq": seq,
    }


def wait_until(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition did not become true")


class ConfigTests(unittest.TestCase):
    def test_manual_config_mid_override_and_secret_safe_repr(self):
        secret = "header.payload.signature"
        value = {
            "credentials_mode": "manual",
            "manual_jwt": secret,
            "origin": "https://zcode.z.ai/",
            "device_mid": "configured-mid",
            "relay_ws_url": "",
        }
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "desktop-config.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            config = relay.RelayConfig.load(path, mid="override-mid")
        self.assertEqual(config.device_mid, "override-mid")
        self.assertEqual(config.origin, relay.FIXED_ORIGIN)
        self.assertEqual(config.ws_url, relay.FIXED_WS_URL)
        self.assertNotIn(secret, repr(config))

    def test_manual_only_and_fixed_origin(self):
        base = {
            "credentials_mode": "manual",
            "manual_jwt": "a.b.c",
            "device_mid": "mid",
            "origin": relay.FIXED_ORIGIN,
        }
        relay.RelayConfig.from_mapping(base)
        with self.assertRaises(relay.ConfigError):
            relay.RelayConfig.from_mapping({**base, "credentials_mode": "auto"})
        with self.assertRaises(relay.ConfigError):
            relay.RelayConfig.from_mapping({
                **base,
                "origin": "https://backup.example",
            })
        with self.assertRaises(relay.ConfigError):
            relay.RelayConfig.from_mapping({
                **base,
                "relay_ws_url": "wss://backup.example/api/v1/remote/ws2",
            })


class SecurityTests(unittest.TestCase):
    def test_phone_origin_is_strict_127_slash_8_with_port(self):
        allowed = [
            "http://127.0.0.0:1",
            "http://127.0.0.1:8787",
            "http://127.255.255.254:65535",
        ]
        rejected = [
            "http://localhost:8787",
            "http://126.0.0.1:8787",
            "http://[::1]:8787",
            "https://127.0.0.1:8787",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://u@127.0.0.1:8787",
            "http://127.0.0.1:8787/",
            "http://127.0.0.1:8787?x=1",
            "http://127.0.0.1:8787,http://127.0.0.2:8787",
            " http://127.0.0.1:8787",
        ]
        for value in allowed:
            with self.subTest(value=value):
                self.assertTrue(relay.is_phone_loopback_origin(value))
        for value in rejected:
            with self.subTest(value=value):
                self.assertFalse(relay.is_phone_loopback_origin(value))

    def test_path_allowlist_and_encoded_absolute_rejection(self):
        for method, path in [
            ("GET", "/"),
            ("GET", "/index.html"),
            ("GET", "/app.js"),
            ("GET", "/vendor/katex/fonts/KaTeX_Main-Regular.woff2"),
            ("GET", "/vendor/pdfjs/cmaps/H.bcmap"),
            ("GET", "/vendor/pdfjs/standard_fonts/LiberationSans-Regular.ttf"),
            ("GET", "/api/auth?next=%2Fsessions"),
            ("HEAD", "/app.js"),
            ("POST", "/api/sessions/" + THREAD + "/send"),
        ]:
            with self.subTest(method=method, path=path):
                relay.validate_bridge_path(method, path)
        for method, path in [
            ("GET", "https://example.com/"),
            ("GET", "//example.com/app.js"),
            ("GET", "/unknown.js"),
            ("POST", "/app.js"),
            ("GET", "/api/%73essions"),
            ("GET", "/api/../sessions"),
            ("GET", "/api//sessions"),
            ("GET", "/api/sessions\\events"),
        ]:
            with self.subTest(method=method, path=path):
                with self.assertRaises(ValueError):
                    relay.validate_bridge_path(method, path)

    def test_header_allowlist_requires_loopback_origin(self):
        result = relay.normalize_request_headers({
            "Origin": PHONE_ORIGIN,
            "Cookie": "bridge=phone",
            "X-CSRF-Token": "csrf",
            "Content-Type": "application/json",
            "Range": "bytes=0-20",
            "If-Range": '"etag"',
        })
        self.assertEqual(result["origin"], PHONE_ORIGIN)
        for headers in [
            {"Cookie": "bridge=phone"},
            {"Origin": "https://127.0.0.1:8787"},
            {"Origin": PHONE_ORIGIN, "Host": "evil"},
            {"Origin": PHONE_ORIGIN, "Authorization": "Bearer secret"},
            {"Origin": PHONE_ORIGIN, "Connection": "keep-alive"},
            {"Origin": PHONE_ORIGIN, "Cookie": "x\r\nInjected: y"},
        ]:
            with self.subTest(headers=headers):
                with self.assertRaises(ValueError):
                    relay.normalize_request_headers(headers)


class FakeTransport:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []
        self.lock = threading.Lock()

    def forward(self, method, path, headers, body):
        with self.lock:
            self.calls.append((method, path, headers, body))
        if self.error is not None:
            raise self.error
        return self.result


class DispatcherTests(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport(relay.ForwardResult(200, {}, b""))
        self.frames = []
        self.changed = threading.Event()

    def sender(self, frame):
        self.frames.append(frame)
        self.changed.set()
        return True

    def test_fragmented_request_and_49k_response_chunks(self):
        response = b"x" * (relay.MAX_CHUNK_BYTES + 1)
        self.transport.result = relay.ForwardResult(
            206,
            {"Set-Cookie": ["a=1", "b=2"], "Content-Range": "bytes 0-1/2"},
            response,
        )
        dispatcher = relay.RelayDispatcher(self.transport)
        try:
            dispatcher.handle(request_start(method="POST", length=6), self.sender)
            dispatcher.handle(request_chunk(THREAD, 0, b"abc"), self.sender)
            dispatcher.handle(request_chunk(THREAD, 1, b"def"), self.sender)
            dispatcher.handle(request_end(THREAD, 2), self.sender)
            wait_until(lambda: any(frame.get("kind") == "end" for frame in self.frames))
        finally:
            dispatcher.close()
        self.assertEqual(self.transport.calls[0][3], b"abcdef")
        start = self.frames[0]
        self.assertEqual(start["kind"], "start")
        self.assertEqual(start["status"], 206)
        self.assertEqual(start["length"], len(response))
        chunks = [frame for frame in self.frames if frame["kind"] == "chunk"]
        raw = [base64.b64decode(frame["data"]) for frame in chunks]
        self.assertEqual([len(item) for item in raw], [relay.MAX_CHUNK_BYTES, 1])
        self.assertEqual(b"".join(raw), response)
        self.assertEqual(self.frames[-1], {
            "zcode_type": "platform-response",
            "requestId": THREAD,
            "bridgeHttp": 1,
            "kind": "end",
            "seq": 2,
        })

    def test_duplicate_sequence_and_replay_are_rejected_without_forwarding(self):
        dispatcher = relay.RelayDispatcher(self.transport)
        try:
            dispatcher.handle(request_start(method="POST", length=2), self.sender)
            dispatcher.handle(request_start(method="POST", length=2), self.sender)
            duplicate = self.frames[0]
            self.assertEqual(duplicate["status"], 409)
            dispatcher.handle(request_chunk(THREAD, 1, b"x"), self.sender)
            empty = "22222222-2222-4222-8222-222222222222"
            dispatcher.handle(request_start(request_id=empty), self.sender)
            self.assertEqual(self.transport.calls, [])
            dispatcher.handle(request_end(empty, 0), self.sender)
            wait_until(lambda: any(frame.get("kind") == "end" for frame in self.frames))
            dispatcher.handle(request_start(request_id=empty), self.sender)
        finally:
            dispatcher.close()
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.transport.calls[0][3], b"")
        statuses = [frame.get("status") for frame in self.frames if frame.get("kind") == "start"]
        self.assertIn(409, statuses)

    def test_sse_is_fixed_406_without_http_forwarding(self):
        dispatcher = relay.RelayDispatcher(self.transport)
        try:
            dispatcher.handle(
                request_start(path="/api/sessions/" + THREAD + "/events"),
                self.sender,
            )
            payload = b"".join(
                base64.b64decode(frame["data"])
                for frame in self.frames
                if frame["kind"] == "chunk"
            )
        finally:
            dispatcher.close()
        self.assertEqual(self.frames[0]["status"], 406)
        self.assertEqual(payload, relay._SAFE_SSE_UNSUPPORTED)
        self.assertNotIn("request rejected", payload.decode("ascii"))
        self.assertEqual(self.transport.calls, [])

    def test_expiry_and_disconnect_make_incomplete_requests_terminal(self):
        now = [0.0]
        dispatcher = relay.RelayDispatcher(
            self.transport,
            clock=lambda: now[0],
            max_age=5.0,
        )
        try:
            dispatcher.handle(request_start(method="POST", length=1), self.sender)
            now[0] = 6.0
            dispatcher.expire()
            self.assertEqual(self.frames[0]["status"], 408)
            other = "22222222-2222-4222-8222-222222222222"
            dispatcher.handle(request_start(request_id=other, method="POST", length=1), self.sender)
            dispatcher.disconnect()
            dispatcher.handle(request_end(other, 0), self.sender)
        finally:
            dispatcher.close()
        self.assertEqual(self.transport.calls, [])

    def test_aggregate_body_limit_is_reserved_at_start(self):
        dispatcher = relay.RelayDispatcher(self.transport)
        first = "33333333-3333-4333-8333-333333333333"
        second = "44444444-4444-4444-8444-444444444444"
        try:
            dispatcher.handle(
                request_start(first, method="POST", length=20 * 1024 * 1024),
                self.sender,
            )
            dispatcher.handle(
                request_start(second, method="POST", length=13 * 1024 * 1024),
                self.sender,
            )
            self.assertEqual(self.frames[0]["status"], 429)
        finally:
            dispatcher.close()

    def test_unknown_write_is_fixed_sanitized_503(self):
        self.transport.error = relay.BridgeWriteUnknown("upstream-may-have-seen-secret")
        dispatcher = relay.RelayDispatcher(self.transport)
        try:
            dispatcher.handle(
                request_start(method="POST", path="/api/sessions/" + THREAD + "/send"),
                self.sender,
            )
            dispatcher.handle(request_end(THREAD, 0), self.sender)
            wait_until(lambda: any(frame.get("kind") == "end" for frame in self.frames))
            payload = b"".join(
                base64.b64decode(frame["data"])
                for frame in self.frames
                if frame["kind"] == "chunk"
            )
        finally:
            dispatcher.close()
        self.assertEqual(self.frames[0]["status"], 503)
        self.assertEqual(payload, relay._SAFE_WRITE_UNKNOWN)
        self.assertNotIn(b"secret", payload)

    def test_empty_body_has_start_and_end_without_chunk(self):
        dispatcher = relay.RelayDispatcher(self.transport)
        try:
            dispatcher.handle(request_start(), self.sender)
            self.assertEqual(self.transport.calls, [])
            dispatcher.handle(request_end(THREAD, 0), self.sender)
            wait_until(lambda: any(frame.get("kind") == "end" for frame in self.frames))
        finally:
            dispatcher.close()
        self.assertEqual([frame["kind"] for frame in self.frames], ["start", "end"])
        self.assertEqual(self.frames[0]["length"], 0)
        self.assertEqual(self.frames[-1]["seq"], 0)


class BridgeHandler(BaseHTTPRequestHandler):
    records = []
    lock = threading.Lock()

    def log_message(self, format, *args):
        pass

    def _record(self, body):
        with self.lock:
            self.records.append({
                "method": self.command,
                "path": self.path,
                "headers": {name.lower(): value for name, value in self.headers.items()},
                "body": body,
            })

    def do_GET(self):
        self._record(b"")
        if self.path == "/api/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            return
        if self.path == "/api/redirect":
            self.send_response(302)
            self.send_header("Location", "https://example.com/private")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"\x00bridge-bytes\xff"
        self.send_response(206)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Range", "bytes 0-12/13")
        self.send_header("ETag", '"phone-etag"')
        self.send_header("Set-Cookie", "first=1; Path=/")
        self.send_header("Set-Cookie", "second=2; Path=/")
        self.send_header("Location", "https://example.com/redirect")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        self._record(body)
        response = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class BridgeTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), BridgeHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.transport = relay.BridgeTransport(
            port=cls.server.server_port,
            timeout=2.0,
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=3)
        cls.server.server_close()

    def setUp(self):
        with BridgeHandler.lock:
            BridgeHandler.records.clear()

    def test_rewrites_origin_keeps_phone_headers_and_multivalue_cookies(self):
        headers = relay.normalize_request_headers({
            "Origin": PHONE_ORIGIN,
            "Cookie": "bridge=phone",
            "X-CSRF-Token": "csrf-from-phone",
            "Range": "bytes=0-12",
            "If-Range": '"phone-etag"',
            "Content-Type": "application/json",
        })
        with mock.patch.dict(os.environ, {
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
        }):
            result = self.transport.forward(
                "GET",
                "/app.js?next=%2Fsessions",
                headers,
                b"",
            )
        self.assertEqual(result.status, 206)
        self.assertEqual(result.body, b"\x00bridge-bytes\xff")
        self.assertEqual(result.headers["set-cookie"], [
            "first=1; Path=/",
            "second=2; Path=/",
        ])
        self.assertEqual(result.headers["etag"], '"phone-etag"')
        self.assertNotIn("location", result.headers)
        record = BridgeHandler.records[-1]
        self.assertEqual(record["path"], "/app.js?next=%2Fsessions")
        self.assertEqual(
            record["headers"]["origin"],
            "http://127.0.0.1:" + str(self.server.server_port),
        )
        self.assertEqual(
            record["headers"]["host"],
            "127.0.0.1:" + str(self.server.server_port),
        )
        self.assertEqual(record["headers"]["cookie"], "bridge=phone")
        self.assertEqual(record["headers"]["x-csrf-token"], "csrf-from-phone")

    def test_redirect_is_returned_without_following_or_location(self):
        headers = relay.normalize_request_headers({"Origin": PHONE_ORIGIN})
        result = self.transport.forward("GET", "/api/redirect", headers, b"")
        self.assertEqual(result.status, 302)
        self.assertNotIn("location", result.headers)
        self.assertEqual(result.body, b"")

    def test_post_body_and_content_type_are_preserved(self):
        headers = relay.normalize_request_headers({
            "Origin": PHONE_ORIGIN,
            "Content-Type": "application/json",
            "Cookie": "bridge=phone",
            "X-CSRF-Token": "csrf-from-phone",
        })
        result = self.transport.forward(
            "POST",
            "/api/sessions/" + THREAD + "/send",
            headers,
            b'{"text":"hello"}',
        )
        self.assertEqual(result.status, 200)
        record = BridgeHandler.records[-1]
        self.assertEqual(record["body"], b'{"text":"hello"}')
        self.assertEqual(record["headers"]["content-type"], "application/json")

    def test_unexpected_event_stream_is_not_buffered(self):
        headers = relay.normalize_request_headers({"Origin": PHONE_ORIGIN})
        started = time.monotonic()
        with self.assertRaises(relay.BridgeTransportError):
            self.transport.forward("GET", "/api/stream", headers, b"")
        self.assertLess(time.monotonic() - started, 1.0)


class FakeApi:
    def __init__(self):
        self.ensure_calls = 0
        self.delete_calls = 0

    def ensure_device(self, mid):
        self.ensure_calls += 1
        return {"device_mid": mid, "device_sid": "sid-1"}

    def delete_device(self, sid):
        self.delete_calls += 1


class LifecycleTests(unittest.TestCase):
    def test_sse_route_detection_is_exact(self):
        self.assertTrue(relay.is_sse_path(
            "/api/sessions/" + THREAD + "/events?after=1"
        ))
        self.assertFalse(relay.is_sse_path(
            "/api/sessions/" + THREAD + "/events-other"
        ))

    def test_kicked_stops_reconnect_and_skips_delete(self):
        config = relay.RelayConfig.from_mapping({
            "credentials_mode": "manual",
            "manual_jwt": "a.b.c",
            "device_mid": "mid",
            "origin": relay.FIXED_ORIGIN,
        })
        dispatcher = relay.RelayDispatcher(FakeTransport(
            relay.ForwardResult(200, {}, b"")
        ))
        relay_service = relay.ZcodeRelay(config, dispatcher=dispatcher)
        api = FakeApi()
        relay_service.api = api
        created = []

        class KickedConnection:
            def __init__(self, *args):
                created.append(args)

            def run_once(self):
                return "kicked"

            def stop(self):
                pass

        with mock.patch.object(relay, "RelayConnection", KickedConnection):
            outcome = relay_service.run()
        relay_service.close(delete_device=True)
        self.assertEqual(outcome, "kicked")
        self.assertEqual(len(created), 1)
        self.assertEqual(api.ensure_calls, 1)
        self.assertEqual(api.delete_calls, 0)
        self.assertTrue(relay_service.kicked)

    def test_pairing_url_uses_config_without_jwt(self):
        config = relay.RelayConfig.from_mapping({
            "credentials_mode": "manual",
            "manual_jwt": "very.secret.jwt",
            "device_mid": "stable-mid",
            "device_name": "Desk & Phone",
            "app_version": "3.18.2",
            "origin": relay.FIXED_ORIGIN,
        })
        value = config.pairing_url("device-sid")
        parts = relay.urllib.parse.urlsplit(value)
        query = relay.urllib.parse.parse_qs(parts.query)
        self.assertEqual(parts.scheme, "https")
        self.assertEqual(parts.netloc, "zcode.z.ai")
        self.assertEqual(parts.path, "/remote/v4")
        self.assertEqual(query["sid"], ["device-sid"])
        self.assertEqual(query["mid"], ["stable-mid"])
        self.assertEqual(query["name"], ["Desk & Phone"])
        self.assertEqual(query["app_version"], ["3.18.2"])
        self.assertNotIn("very.secret.jwt", value)

    def test_auth_logs_ready_url_once_and_only_state_changes(self):
        config = relay.RelayConfig.from_mapping({
            "credentials_mode": "manual",
            "manual_jwt": "very.secret.jwt",
            "device_mid": "stable-mid",
            "device_name": "Desk Phone",
            "app_version": "3.18.2",
            "origin": relay.FIXED_ORIGIN,
        })
        dispatcher = relay.RelayDispatcher(FakeTransport(
            relay.ForwardResult(200, {}, b"")
        ))
        connection = relay.RelayConnection(
            config,
            object(),
            "device-sid",
            dispatcher,
        )
        auth = {
            "type": "auth_ack",
            "device_sid": "device-sid",
            "pair_status": "waiting",
        }
        try:
            with mock.patch.object(relay.LOG, "info") as info:
                connection._receive(json.dumps(auth))
                connection._receive(json.dumps(auth))
                connection._receive(json.dumps({
                    "type": "pair_status_ack",
                    "pair_status": "waiting",
                }))
                connection._receive(json.dumps({
                    "type": "pair_status_ack",
                    "pair_status": "matched",
                }))
                connection._receive(json.dumps({
                    "type": "pair_status_ack",
                    "pair_status": "matched",
                }))
        finally:
            dispatcher.close()
        expected = [
            mock.call("ZCR_READY websocket authenticated"),
            mock.call("ZCR_PAIR_URL %s", config.pairing_url("device-sid")),
            mock.call("ZCR_STATE %s", "waiting_terminal"),
            mock.call("ZCR_STATE %s", "matched"),
        ]
        self.assertEqual(info.call_args_list, expected)
        rendered = str(info.call_args_list)
        self.assertNotIn("very.secret.jwt", rendered)
        self.assertNotIn("Cookie", rendered)
        self.assertNotIn("CSRF", rendered)

    def test_kicked_log_is_fixed_and_explicit(self):
        dispatcher = relay.RelayDispatcher(FakeTransport(
            relay.ForwardResult(200, {}, b"")
        ))
        connection = relay.RelayConnection(
            relay.RelayConfig.from_mapping({
                "credentials_mode": "manual",
                "manual_jwt": "very.secret.jwt",
                "device_mid": "mid",
                "origin": relay.FIXED_ORIGIN,
            }),
            object(),
            "sid",
            dispatcher,
        )
        try:
            with mock.patch.object(relay.LOG, "warning") as warning:
                connection._receive(json.dumps({
                    "type": "error",
                    "code": "KICKED",
                }))
        finally:
            dispatcher.close()
        self.assertEqual(connection._outcome, "kicked")
        warning.assert_called_once_with(
            "ZCR_STOP reason=KICKED; reconnect disabled"
        )
        self.assertNotIn("very.secret.jwt", str(warning.call_args_list))

    def test_signal_handler_requests_graceful_stop(self):
        service = mock.Mock()
        with mock.patch.object(relay.signal, "signal") as register:
            relay._install_stop_handlers(service)
        self.assertTrue(register.called)
        handler = register.call_args_list[0].args[1]
        with mock.patch.object(relay.LOG, "info") as info:
            handler(15, None)
        service.stop.assert_called_once_with()
        info.assert_called_once_with("ZCR_STOP reason=signal")
    def test_heartbeat_is_required_five_seconds(self):
        self.assertEqual(relay.HEARTBEAT_SECONDS, 5.0)
        self.assertEqual(relay.BRIDGE_HOST, "127.0.0.1")
        self.assertEqual(relay.BRIDGE_PORT, 8787)


if __name__ == "__main__":
    unittest.main()
