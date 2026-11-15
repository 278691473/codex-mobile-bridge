"""Desktop HTTP transport over the ZCode device relay.

This module is deliberately independent from the web UI. It connects as one
ZCode device, receives the phone HTTP protocol described by bridgeHttp 1,
and forwards each request only to the local Codex Mobile gateway at
http://127.0.0.1:8787.

Manual ZCode credentials are read from the private desktop config. JWT,
bridge login cookies, CSRF tokens, request bodies, and upstream error bodies
are never logged.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import http.client
import ipaddress
import json
import logging
import re
import signal
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

import websocket

from bridge.web_assets import is_public_file_path


LOG = logging.getLogger("zcode_relay")

FIXED_ORIGIN = "https://zcode.z.ai"
FIXED_REMOTE_BASE = FIXED_ORIGIN + "/remote/v4"
FIXED_WS_URL = "wss://zcode.z.ai/api/v1/remote/ws2"
WS_HOST = "zcode.z.ai"

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 8787
BRIDGE_ORIGIN = "http://127.0.0.1:8787"

MAX_REQUEST_BODY = 20 * 1024 * 1024
MAX_AGGREGATE_BODY = 32 * 1024 * 1024
MAX_RESPONSE_BODY = 20 * 1024 * 1024
MAX_CHUNK_BYTES = 49_152
MAX_ACTIVE_REQUESTS = 16
MAX_SEEN_REQUESTS = 4096
MAX_REQUEST_AGE = 300.0
MAX_ENVELOPE_BYTES = 1024 * 1024
MAX_CONTROL_RESPONSE = 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
HEARTBEAT_SECONDS = 5.0
WATCHDOG_SECONDS = 15.0
HTTP_TIMEOUT_SECONDS = 30.0

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{21}[AQgw]$")
_SSE_ROUTE = re.compile(
    r"^/api/sessions/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/events$"
)

_REQUEST_HEADERS = frozenset({
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "content-range",
    "content-type",
    "cookie",
    "etag",
    "if-match",
    "if-none-match",
    "if-range",
    "origin",
    "pragma",
    "range",
    "user-agent",
    "x-csrf-token",
})

_RESPONSE_HEADERS = frozenset({
    "accept-ranges",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-length",
    "content-range",
    "content-security-policy",
    "content-type",
    "etag",
    "expires",
    "last-modified",
    "permissions-policy",
    "pragma",
    "range",
    "referrer-policy",
    "set-cookie",
    "vary",
    "x-content-type-options",
    "x-frame-options",
})

_SAFE_REJECT = b'{"error":"zcode relay request rejected"}'
_SAFE_UNAVAILABLE = b'{"error":"zcode relay upstream unavailable"}'
_SAFE_WRITE_UNKNOWN = b'{"error":"zcode relay write result unknown"}'
_SAFE_SSE_UNSUPPORTED = b'{"error":"zcode relay SSE is not supported"}'


class ConfigError(ValueError):
    """Configuration is unusable; its contents are never included."""


class BridgeTransportError(RuntimeError):
    pass


class BridgeWriteUnknown(BridgeTransportError):
    pass


@dataclass(frozen=True)
class RelayConfig:
    manual_jwt: str = field(repr=False)
    device_mid: str
    device_name: str = "codex-mobile-zcode-relay"
    app_version: str = "1.0"
    origin: str = FIXED_ORIGIN
    ws_url: str = FIXED_WS_URL

    @classmethod
    def load(cls, path: str | Path, mid: str | None = None) -> "RelayConfig":
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        except (OSError, ValueError, TypeError):
            raise ConfigError("desktop config is unavailable or invalid") from None
        if not isinstance(value, dict):
            raise ConfigError("desktop config must be an object")
        return cls.from_mapping(value, mid=mid)

    @classmethod
    def from_mapping(cls, value: Mapping, mid: str | None = None) -> "RelayConfig":
        if value.get("credentials_mode") != "manual":
            raise ConfigError("manual ZCode credentials are required")
        jwt = value.get("manual_jwt")
        if not isinstance(jwt, str) or jwt.count(".") != 2 or any(
            not part for part in jwt.split(".")
        ):
            raise ConfigError("manual_jwt is invalid")
        origin = value.get("origin", FIXED_ORIGIN)
        if not isinstance(origin, str) or origin.rstrip("/") != FIXED_ORIGIN:
            raise ConfigError("ZCode origin is fixed")
        ws_url = value.get("relay_ws_url") or FIXED_WS_URL
        if not isinstance(ws_url, str) or ws_url != FIXED_WS_URL:
            raise ConfigError("ZCode relay endpoint is fixed")
        device_mid = mid if mid is not None else value.get("device_mid")
        if not isinstance(device_mid, str) or not 1 <= len(device_mid) <= 128:
            raise ConfigError("device_mid is invalid")
        device_name = value.get("device_name") or "codex-mobile-zcode-relay"
        app_version = value.get("app_version") or "1.0"
        if not isinstance(device_name, str) or not 1 <= len(device_name) <= 128:
            raise ConfigError("device_name is invalid")
        if not isinstance(app_version, str) or not 1 <= len(app_version) <= 64:
            raise ConfigError("app_version is invalid")
        return cls(
            manual_jwt=jwt,
            device_mid=device_mid,
            device_name=device_name,
            app_version=app_version,
        )

    def pairing_url(self, device_sid: str) -> str:
        query = urllib.parse.urlencode({
            "sid": device_sid,
            "mid": self.device_mid,
            "name": self.device_name,
            "app_version": self.app_version,
        })
        return FIXED_REMOTE_BASE + "?" + query


def is_phone_loopback_origin(value: object) -> bool:
    """Return true only for http://127.0.0.0/8:<port> with no extra URL parts."""
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if any(char in value for char in ("\\", "?", "#", "@")) or "," in value:
        return False
    try:
        parts = urllib.parse.urlsplit(value)
        port = parts.port
        address = ipaddress.IPv4Address(parts.hostname or "")
    except (ValueError, TypeError):
        return False
    return (
        parts.scheme == "http"
        and parts.path == ""
        and parts.query == ""
        and parts.fragment == ""
        and parts.username is None
        and parts.password is None
        and port is not None
        and 1 <= port <= 65535
        and address in ipaddress.IPv4Network("127.0.0.0/8")
    )


def is_sse_path(value: str) -> bool:
    return bool(_SSE_ROUTE.fullmatch(urllib.parse.urlsplit(value).path))


def validate_bridge_path(method: str, value: object) -> str:
    """Validate the exact request target accepted by the local gateway proxy."""
    if method not in ("GET", "HEAD", "POST"):
        raise ValueError("method is not allowed")
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise ValueError("path is invalid")
    if value != value.strip() or any(ord(char) < 32 or ord(char) >= 127 for char in value):
        raise ValueError("path contains invalid characters")
    if not value.startswith("/") or value.startswith("//"):
        raise ValueError("path must be relative to the fixed bridge")
    if "#" in value or "\\" in value:
        raise ValueError("path contains a forbidden delimiter")
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        raise ValueError("path is invalid") from None
    if parts.scheme or parts.netloc or parts.fragment:
        raise ValueError("absolute and fragmented targets are forbidden")
    raw_path = parts.path
    if not raw_path.startswith("/") or raw_path.startswith("//") or "%" in raw_path:
        raise ValueError("encoded or absolute paths are forbidden")
    segments = raw_path.split("/")[1:]
    if any(not segment for segment in segments[:-1]) or any(
        segment in (".", "..") for segment in segments
    ):
        raise ValueError("dot or empty segments are forbidden")
    if method in ("GET", "HEAD"):
        static = is_public_file_path(raw_path)
        if not static and not raw_path.startswith("/api/"):
            raise ValueError("static path is not allowlisted")
    elif not raw_path.startswith("/api/"):
        raise ValueError("writes are limited to the original API gateway")
    return value


def normalize_request_headers(value: object) -> dict[str, str | tuple[str, ...]]:
    """Validate a finite end-to-end request header allowlist."""
    if not isinstance(value, dict):
        raise ValueError("headers must be an object")
    result: dict[str, str | tuple[str, ...]] = {}
    total = 0
    for name, raw_values in value.items():
        if not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name):
            raise ValueError("header name is invalid")
        lower = name.lower()
        if lower in result:
            raise ValueError("duplicate header")
        if lower not in _REQUEST_HEADERS:
            raise ValueError("header is not allowed")
        values = [raw_values] if isinstance(raw_values, str) else raw_values
        if not isinstance(values, (list, tuple)) or not values or len(values) > 16:
            raise ValueError("header value is invalid")
        checked = []
        for item in values:
            if not isinstance(item, str) or len(item) > 8192:
                raise ValueError("header value is invalid")
            if any(ord(char) < 32 or ord(char) == 127 for char in item):
                raise ValueError("header value is invalid")
            total += len(item.encode("utf-8")) + len(lower) + 4
            checked.append(item)
        result[lower] = checked[0] if len(checked) == 1 else tuple(checked)
    if total > MAX_HEADER_BYTES:
        raise ValueError("headers are too large")
    origin = result.get("origin")
    if not isinstance(origin, str) or not is_phone_loopback_origin(origin):
        raise ValueError("phone origin is not a loopback origin")
    return result


def _valid_request_id(value: object) -> str:
    if not isinstance(value, str) or not _UUID_RE.fullmatch(value):
        raise ValueError("requestId must be a UUID")
    try:
        uuid.UUID(value)
    except ValueError:
        raise ValueError("requestId must be a UUID") from None
    return value.lower()


def _new_envelope(msg_type: str, **fields) -> dict:
    return {"type": msg_type, **fields, "client_ts": int(time.time())}


def _encode_envelope(value: dict) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ValueError("envelope is too large")
    return raw.decode("utf-8")


def _parse_incoming(raw: object) -> dict | None:
    try:
        if isinstance(raw, bytes):
            value = json.loads(raw.decode("utf-8"))
        elif isinstance(raw, str):
            value = json.loads(raw)
        else:
            return None
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    if value.get("type") == "auth_ack":
        return value if isinstance(value.get("device_sid"), str) else None
    if value.get("type") == "pair_status_ack":
        return value if value.get("pair_status") in ("waiting", "matched") else None
    if value.get("type") == "data" and isinstance(value.get("payload"), dict):
        return value
    if value.get("type") == "error" and value.get("code") in {
        "AUTH_FAILED", "WRONG_PARAM", "KICKED", "INTERNAL", "DEVICE_OFFLINE"
    }:
        return value
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class RelayApiError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class RelayApi:
    def __init__(self, origin: str, jwt_provider: Callable[[], str]):
        if origin.rstrip("/") != FIXED_ORIGIN:
            raise ConfigError("ZCode origin is fixed")
        self.origin = FIXED_ORIGIN
        self.jwt_provider = jwt_provider
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def _request(self, method: str, path: str, body: dict | None = None) -> object:
        if not path.startswith("/api/v1/remote/") or "://" in path:
            raise RelayApiError("invalid relay API path")
        data = None
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self.jwt_provider(),
        }
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            FIXED_ORIGIN + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=15.0) as response:
                raw = response.read(MAX_CONTROL_RESPONSE + 1)
                status = response.status
        except urllib.error.HTTPError as error:
            error.close()
            raise RelayApiError("relay API rejected the request", status=error.code) from None
        except (urllib.error.URLError, OSError):
            raise RelayApiError("relay API network failure") from None
        if status < 200 or status >= 300 or len(raw) > MAX_CONTROL_RESPONSE:
            raise RelayApiError("relay API response was invalid", status=status)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise RelayApiError("relay API response was not JSON") from None
        if not isinstance(parsed, dict) or parsed.get("code") != 0:
            raise RelayApiError("relay API returned an error")
        return parsed.get("data")

    def list_devices(self) -> list:
        data = self._request("GET", "/api/v1/remote/device")
        return data if isinstance(data, list) else []

    def ensure_device(self, device_mid: str) -> dict:
        for item in self.list_devices():
            if isinstance(item, dict) and item.get("device_mid") == device_mid:
                sid = item.get("device_sid")
                if isinstance(sid, str) and sid:
                    return item
        data = self._request("POST", "/api/v1/remote/device", {"device_mid": device_mid})
        if not isinstance(data, dict):
            raise RelayApiError("device response was invalid")
        sid = data.get("device_sid")
        if not isinstance(sid, str) or not sid or len(sid) > 512:
            raise RelayApiError("device response lacked device_sid")
        return data

    def delete_device(self, device_sid: str) -> None:
        self._request(
            "POST",
            "/api/v1/remote/device/delete",
            {"device_sid": device_sid},
        )

    def issue_token(self) -> str:
        data = self._request("POST", "/api/v1/remote/token", {"role": "device"})
        token = data.get("token") if isinstance(data, dict) else None
        expires = data.get("expires_in") if isinstance(data, dict) else None
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            raise RelayApiError("device token response was invalid")
        if type(expires) is not int or expires <= 0:
            raise RelayApiError("device token lifetime was invalid")
        return token

    def ws_url(self, token: str, device_mid: str) -> str:
        query = urllib.parse.urlencode({"token": token, "mid": device_mid})
        return FIXED_WS_URL + "?" + query


@dataclass(frozen=True)
class ForwardResult:
    status: int
    headers: dict[str, str | list[str]]
    body: bytes


class BridgeTransport:
    """No-proxy, no-redirect HTTP client pinned to the local gateway."""

    def __init__(self, port: int = BRIDGE_PORT, timeout: float = HTTP_TIMEOUT_SECONDS):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("bridge port is invalid")
        self.port = port
        self.timeout = timeout

    def _headers(self, response: http.client.HTTPResponse) -> dict[str, str | list[str]]:
        values: dict[str, list[str]] = {}
        for name, value in response.getheaders():
            lower = name.lower()
            if lower not in _RESPONSE_HEADERS:
                continue
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                continue
            values.setdefault(lower, []).append(value)
        return {
            name: items[0] if len(items) == 1 else items
            for name, items in values.items()
        }

    def forward(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str | tuple[str, ...]],
        body: bytes,
    ) -> ForwardResult:
        validate_bridge_path(method, path)
        origin = headers.get("origin")
        if not isinstance(origin, str) or not is_phone_loopback_origin(origin):
            raise BridgeTransportError("phone origin is invalid")

        connection = http.client.HTTPConnection(
            BRIDGE_HOST,
            self.port,
            timeout=self.timeout,
        )
        write_started = False
        try:
            connection.putrequest(
                method,
                path,
                skip_host=True,
                skip_accept_encoding=True,
            )
            connection.putheader("Host", "127.0.0.1:" + str(self.port))
            forwarded_origin = (
                BRIDGE_ORIGIN
                if self.port == BRIDGE_PORT
                else "http://127.0.0.1:" + str(self.port)
            )
            connection.putheader("Origin", forwarded_origin)
            connection.putheader("Sec-Fetch-Site", "same-origin")
            connection.putheader("Connection", "close")
            for name, raw_values in headers.items():
                if name == "origin":
                    continue
                values = (raw_values,) if isinstance(raw_values, str) else raw_values
                for value in values:
                    connection.putheader(name, value)
            if method == "POST":
                connection.putheader("Content-Length", str(len(body)))
            write_started = method == "POST"
            connection.endheaders(body if method == "POST" else None)
            response = connection.getresponse()
            content_type = (response.getheader("Content-Type") or "").lower()
            if content_type.startswith("text/event-stream"):
                raise BridgeTransportError("streaming responses are unsupported")
            content_length = response.getheader("Content-Length")
            if (
                method != "HEAD"
                and isinstance(content_length, str)
                and content_length.isdigit()
                and int(content_length) > MAX_RESPONSE_BODY
            ):
                raise BridgeTransportError("bridge response is too large")
            response_body = response.read(MAX_RESPONSE_BODY + 1)
            if len(response_body) > MAX_RESPONSE_BODY:
                raise BridgeTransportError("bridge response is too large")
            return ForwardResult(
                status=response.status,
                headers=self._headers(response),
                body=response_body,
            )
        except BridgeTransportError:
            if write_started and method == "POST":
                raise BridgeWriteUnknown("bridge write result is unknown") from None
            raise
        except Exception:
            if write_started and method == "POST":
                raise BridgeWriteUnknown("bridge write result is unknown") from None
            raise BridgeTransportError("bridge request failed") from None
        finally:
            connection.close()


@dataclass
class _Pending:
    request_id: str
    key: str
    method: str
    path: str
    headers: dict[str, str | tuple[str, ...]]
    expected: int
    sender: Callable[[dict], bool]
    generation: int
    created: float
    next_seq: int = 0
    body: bytearray = field(default_factory=bytearray)
    released: bool = False


class RelayDispatcher:
    """Bounds, validates, and executes independent bridgeHttp v1 requests."""

    def __init__(
        self,
        transport: BridgeTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        max_age: float = MAX_REQUEST_AGE,
    ):
        self.transport = transport or BridgeTransport()
        self.clock = clock
        self.max_age = max_age
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(MAX_ACTIVE_REQUESTS)
        self._active: dict[str, _Pending] = {}
        self._seen: dict[str, float] = {}
        self._reserved = 0
        self._generation = 0
        self._executor = ThreadPoolExecutor(
            max_workers=MAX_ACTIVE_REQUESTS,
            thread_name_prefix="zcode-bridge-http",
        )

    def handle(self, payload: object, sender: Callable[[dict], bool]) -> None:
        if not isinstance(payload, dict):
            return
        if payload.get("zcode_type") != "platform-request":
            return
        try:
            key = _valid_request_id(payload.get("requestId"))
        except ValueError:
            return
        try:
            kind = payload.get("kind")
            if kind == "start":
                self._start(payload, key, sender)
            elif kind == "chunk":
                self._chunk(payload, key, sender)
            elif kind == "end":
                self._end(payload, key, sender)
            else:
                self._reject(sender, payload.get("requestId"), 400, _SAFE_REJECT)
        except _ProtocolReject as error:
            self._reject(
                sender,
                payload.get("requestId"),
                error.status,
                error.body,
            )
        except Exception:
            self._reject(sender, payload.get("requestId"), 400, _SAFE_REJECT)

    def _expire_seen_locked(self, now: float) -> None:
        for key, expires in list(self._seen.items()):
            if expires > now:
                break
            self._seen.pop(key, None)

    def _release_locked(self, pending: _Pending) -> None:
        if pending.released:
            return
        pending.released = True
        self._reserved -= pending.expected
        self._slots.release()

    def _fail_active_locked(self, pending: _Pending) -> None:
        self._active.pop(pending.key, None)
        self._release_locked(pending)

    def _start(
        self,
        payload: dict,
        key: str,
        sender: Callable[[dict], bool],
    ) -> None:
        expected_fields = {
            "zcode_type",
            "requestId",
            "bridgeHttp",
            "kind",
            "method",
            "path",
            "headers",
            "length",
        }
        if (
            set(payload) != expected_fields
            or type(payload.get("bridgeHttp")) is not int
            or payload.get("bridgeHttp") != 1
        ):
            raise _ProtocolReject(400)
        method = payload.get("method")
        path = validate_bridge_path(method, payload.get("path"))
        headers = normalize_request_headers(payload.get("headers"))
        length = payload.get("length")
        if type(length) is not int or length < 0 or length > MAX_REQUEST_BODY:
            raise _ProtocolReject(413)
        if method in ("GET", "HEAD") and length != 0:
            raise _ProtocolReject(400)
        if method == "GET" and is_sse_path(path):
            raise _ProtocolReject(406, _SAFE_SSE_UNSUPPORTED)

        now = self.clock()
        with self._lock:
            self._expire_seen_locked(now)
            if key in self._seen or key in self._active:
                raise _ProtocolReject(409)
            if len(self._seen) >= MAX_SEEN_REQUESTS:
                raise _ProtocolReject(429)
            if not self._slots.acquire(blocking=False):
                raise _ProtocolReject(429)
            if self._reserved + length > MAX_AGGREGATE_BODY:
                self._slots.release()
                raise _ProtocolReject(429)
            self._reserved += length
            self._seen[key] = now + self.max_age
            pending = _Pending(
                request_id=payload["requestId"],
                key=key,
                method=method,
                path=path,
                headers=headers,
                expected=length,
                sender=sender,
                generation=self._generation,
                created=now,
            )
            self._active[key] = pending

    def _chunk(
        self,
        payload: dict,
        key: str,
        sender: Callable[[dict], bool],
    ) -> None:
        if (
            set(payload) != {
                "zcode_type",
                "requestId",
                "bridgeHttp",
                "kind",
                "seq",
                "data",
            }
            or type(payload.get("bridgeHttp")) is not int
            or payload.get("bridgeHttp") != 1
        ):
            raise _ProtocolReject(400)
        seq = payload.get("seq")
        data = payload.get("data")
        if type(seq) is not int or seq < 0 or not isinstance(data, str):
            raise _ProtocolReject(400)
        try:
            raw = base64.b64decode(data, validate=True)
        except (ValueError, binascii.Error):
            raise _ProtocolReject(400) from None
        if not raw or len(raw) > MAX_CHUNK_BYTES:
            raise _ProtocolReject(413)
        with self._lock:
            pending = self._active.get(key)
            if pending is None or pending.sender != sender:
                raise _ProtocolReject(409)
            if seq != pending.next_seq:
                self._fail_active_locked(pending)
                raise _ProtocolReject(409)
            if len(pending.body) + len(raw) > pending.expected:
                self._fail_active_locked(pending)
                raise _ProtocolReject(413)
            pending.body.extend(raw)
            pending.next_seq += 1

    def _end(
        self,
        payload: dict,
        key: str,
        sender: Callable[[dict], bool],
    ) -> None:
        if (
            set(payload) != {
                "zcode_type",
                "requestId",
                "bridgeHttp",
                "kind",
                "seq",
            }
            or type(payload.get("bridgeHttp")) is not int
            or payload.get("bridgeHttp") != 1
        ):
            raise _ProtocolReject(400)
        seq = payload.get("seq")
        if type(seq) is not int or seq < 0:
            raise _ProtocolReject(400)
        with self._lock:
            pending = self._active.get(key)
            if pending is None or pending.sender != sender:
                raise _ProtocolReject(409)
            if seq != pending.next_seq:
                self._fail_active_locked(pending)
                raise _ProtocolReject(409)
            if len(pending.body) != pending.expected:
                self._fail_active_locked(pending)
                raise _ProtocolReject(400)
            self._active.pop(key, None)
        self._execute_later(pending)

    def _complete(self, pending: _Pending) -> None:
        with self._lock:
            if self._active.get(pending.key) is not pending:
                return
            self._active.pop(pending.key, None)
        self._execute_later(pending)

    def _execute_later(self, pending: _Pending) -> None:
        try:
            self._executor.submit(self._execute, pending)
        except RuntimeError:
            with self._lock:
                self._release_locked(pending)
            self._reject(
                pending.sender,
                pending.request_id,
                503,
                _SAFE_UNAVAILABLE,
            )

    def _execute(self, pending: _Pending) -> None:
        try:
            result = self.transport.forward(
                pending.method,
                pending.path,
                pending.headers,
                bytes(pending.body),
            )
            with self._lock:
                stale = pending.generation != self._generation
            if not stale:
                self._reply(
                    pending.sender,
                    pending.request_id,
                    result.status,
                    result.headers,
                    result.body,
                )
        except BridgeWriteUnknown:
            with self._lock:
                stale = pending.generation != self._generation
            if not stale:
                self._reject(
                    pending.sender,
                    pending.request_id,
                    503,
                    _SAFE_WRITE_UNKNOWN,
                )
        except BridgeTransportError:
            with self._lock:
                stale = pending.generation != self._generation
            if not stale:
                self._reject(
                    pending.sender,
                    pending.request_id,
                    502,
                    _SAFE_UNAVAILABLE,
                )
        except Exception:
            with self._lock:
                stale = pending.generation != self._generation
            if not stale:
                self._reject(
                    pending.sender,
                    pending.request_id,
                    502,
                    _SAFE_UNAVAILABLE,
                )
        finally:
            with self._lock:
                self._release_locked(pending)

    def _reply(
        self,
        sender: Callable[[dict], bool],
        request_id: str,
        status: int,
        headers: dict[str, str | list[str]],
        body: bytes,
    ) -> None:
        common = {
            "zcode_type": "platform-response",
            "requestId": request_id,
            "bridgeHttp": 1,
        }
        if not sender({
            **common,
            "kind": "start",
            "status": status,
            "headers": headers,
            "length": len(body),
        }):
            return
        seq = 0
        for offset in range(0, len(body), MAX_CHUNK_BYTES):
            chunk = body[offset:offset + MAX_CHUNK_BYTES]
            if not sender({
                **common,
                "kind": "chunk",
                "seq": seq,
                "data": base64.b64encode(chunk).decode("ascii"),
            }):
                return
            seq += 1
        sender({**common, "kind": "end", "seq": seq})

    def _reject(
        self,
        sender: Callable[[dict], bool],
        request_id: object,
        status: int,
        body: bytes,
    ) -> None:
        if not isinstance(request_id, str) or not _UUID_RE.fullmatch(request_id):
            return
        self._reply(
            sender,
            request_id,
            status,
            {
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": str(len(body)),
                "Cache-Control": "no-store",
            },
            body,
        )

    def expire(self) -> None:
        now = self.clock()
        expired = []
        with self._lock:
            self._expire_seen_locked(now)
            for pending in list(self._active.values()):
                if now - pending.created >= self.max_age:
                    self._fail_active_locked(pending)
                    expired.append(pending)
        for pending in expired:
            self._reject(
                pending.sender,
                pending.request_id,
                408,
                _SAFE_REJECT,
            )

    def disconnect(self) -> None:
        """Drop every incomplete request from the current WS generation."""
        with self._lock:
            self._generation += 1
            for pending in list(self._active.values()):
                self._fail_active_locked(pending)

    def close(self, wait: bool = False) -> None:
        self.disconnect()
        self._executor.shutdown(wait=wait, cancel_futures=True)


class _ProtocolReject(RuntimeError):
    def __init__(self, status: int, body: bytes = _SAFE_REJECT):
        super().__init__("relay protocol rejected")
        self.status = status
        self.body = body


class RelayConnection:
    """One WS session. A new device token is requested by every run_once call."""

    def __init__(
        self,
        config: RelayConfig,
        api: RelayApi,
        device_sid: str,
        dispatcher: RelayDispatcher,
    ):
        self.config = config
        self.api = api
        self.device_sid = device_sid
        self.dispatcher = dispatcher
        self._ws: websocket.WebSocket | None = None
        self._stop = threading.Event()
        self._send_lock = threading.Lock()
        self._heartbeat: threading.Thread | None = None
        self._last_receive = 0.0
        self._authenticated = False
        self._ready_logged = False
        self._pair_status = ""
        self._kicked_logged = False
        self._outcome = "disconnected"

    def stop(self) -> None:
        self._outcome = "stopped"
        self._stop.set()
        self._close_socket()

    def run_once(self) -> str:
        token = self.api.issue_token()
        ws = websocket.WebSocket()
        try:
            ws.connect(
                self.api.ws_url(token, self.config.device_mid),
                origin=FIXED_ORIGIN,
                timeout=20.0,
                http_no_proxy=[WS_HOST],
                redirect_limit=0,
            )
            response = getattr(ws, "handshake_response", None)
            if getattr(response, "status", 101) != 101:
                raise websocket.WebSocketException(
                    "relay handshake was not upgraded"
                )
            ws.settimeout(1.0)
            self._ws = ws
            self._last_receive = time.monotonic()
            if not self._send_envelope(_new_envelope(
                "auth_init",
                device_sid=self.device_sid,
                meta={
                    "name": self.config.device_name,
                    "platform": "windows",
                    "version": self.config.app_version,
                },
            )):
                return self._outcome
            self._heartbeat = threading.Thread(
                target=self._heartbeat_loop,
                name="zcode-relay-heartbeat",
                daemon=True,
            )
            self._heartbeat.start()
            while not self._stop.is_set():
                try:
                    opcode, data = ws.recv_data(control_frame=True)
                except websocket.WebSocketTimeoutException:
                    self._expire_and_watchdog()
                    continue
                if opcode == websocket.ABNF.OPCODE_CLOSE:
                    break
                if opcode == websocket.ABNF.OPCODE_PING:
                    with self._send_lock:
                        ws.pong(data)
                    continue
                if opcode == websocket.ABNF.OPCODE_PONG:
                    continue
                if opcode not in (
                    websocket.ABNF.OPCODE_TEXT,
                    websocket.ABNF.OPCODE_BINARY,
                ):
                    continue
                if len(data) > MAX_ENVELOPE_BYTES:
                    continue
                self._last_receive = time.monotonic()
                self._receive(data)
            return self._outcome
        except Exception:
            return self._outcome
        finally:
            self._stop.set()
            if self._heartbeat is not None:
                self._heartbeat.join(timeout=2.0)
            self._close_socket()
            self.dispatcher.disconnect()

    def _expire_and_watchdog(self) -> None:
        self.dispatcher.expire()
        if time.monotonic() - self._last_receive > WATCHDOG_SECONDS:
            self._outcome = "disconnected"
            self._stop.set()
            self._close_socket()

    def _receive(self, raw: object) -> None:
        message = _parse_incoming(raw)
        if message is None:
            return
        kind = message.get("type")
        if kind == "auth_ack":
            if message.get("device_sid") == self.device_sid:
                self._authenticated = True
                self._outcome = "authenticated"
                self._log_ready(message.get("pair_status"))
            return
        if kind == "pair_status_ack":
            if self._authenticated:
                self._update_pair_status(message.get("pair_status"))
            return
        if kind == "data":
            payload = message.get("payload")
            if self._authenticated and isinstance(payload, dict):
                self.dispatcher.handle(payload, self.send_payload)
            return
        if kind == "error":
            if message.get("code") == "KICKED":
                self._outcome = "kicked"
                if not self._kicked_logged:
                    self._kicked_logged = True
                    LOG.warning("ZCR_STOP reason=KICKED; reconnect disabled")
            else:
                self._outcome = "relay_error"
            self._stop.set()
            self._close_socket()

    def _log_ready(self, pair_status: object) -> None:
        if not self._ready_logged:
            self._ready_logged = True
            LOG.info("ZCR_READY websocket authenticated")
            LOG.info("ZCR_PAIR_URL %s", self.config.pairing_url(self.device_sid))
        self._update_pair_status(pair_status or "waiting")

    def _update_pair_status(self, pair_status: object) -> None:
        labels = {"waiting": "waiting_terminal", "matched": "matched"}
        label = labels.get(pair_status)
        if label is None or label == self._pair_status:
            return
        self._pair_status = label
        LOG.info("ZCR_STATE %s", label)

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(HEARTBEAT_SECONDS):
            if not self._send_envelope(_new_envelope("pair_status_query")):
                self._outcome = "disconnected"
                self._stop.set()
                self._close_socket()
                return

    def send_payload(self, payload: dict) -> bool:
        return self._send_envelope(_new_envelope("data", payload=payload))

    def _send_envelope(self, envelope: dict) -> bool:
        ws = self._ws
        if ws is None or self._stop.is_set():
            return False
        try:
            raw = _encode_envelope(envelope)
        except (TypeError, ValueError):
            return False
        with self._send_lock:
            try:
                ws.send(raw)
                return True
            except Exception:
                self._outcome = "disconnected"
                self._stop.set()
                return False

    def _close_socket(self) -> None:
        ws = self._ws
        if ws is None:
            return
        try:
            ws.close()
        except Exception:
            pass


class ZcodeRelay:
    """Register once and reconnect with a fresh device token unless kicked."""

    def __init__(self, config: RelayConfig, dispatcher: RelayDispatcher | None = None):
        self.config = config
        self.dispatcher = dispatcher or RelayDispatcher()
        self.api = RelayApi(config.origin, lambda: config.manual_jwt)
        self._stop = threading.Event()
        self._connection: RelayConnection | None = None
        self._connection_lock = threading.Lock()
        self.device_sid = ""
        self.kicked = False

    def stop(self) -> None:
        self._stop.set()
        with self._connection_lock:
            connection = self._connection
        if connection is not None:
            connection.stop()

    def run(self) -> str:
        outcome = "stopped"
        backoff = 1.0
        while not self._stop.is_set():
            try:
                device = self.api.ensure_device(self.config.device_mid)
                sid = device.get("device_sid")
                if not isinstance(sid, str) or not sid:
                    raise RelayApiError("device response was invalid")
                self.device_sid = sid
                connection = RelayConnection(
                    self.config,
                    self.api,
                    sid,
                    self.dispatcher,
                )
                with self._connection_lock:
                    self._connection = connection
                outcome = connection.run_once()
            except RelayApiError:
                outcome = "disconnected"
            except Exception:
                outcome = "disconnected"
            finally:
                with self._connection_lock:
                    self._connection = None
            if outcome == "kicked":
                self.kicked = True
                break
            LOG.info("ZCR_STATE disconnected")
            if self._stop.wait(backoff):
                break
            backoff = min(30.0, backoff * 2.0)
        return outcome

    def delete_registered_device(self) -> None:
        if self.device_sid and not self.kicked:
            self.api.delete_device(self.device_sid)

    def close(self, delete_device: bool = False) -> None:
        self.stop()
        if delete_device:
            try:
                self.delete_registered_device()
            except Exception:
                pass
        self.dispatcher.close()


def _install_stop_handlers(relay_service: ZcodeRelay) -> None:
    def stop_handler(_signum, _frame):
        LOG.info("ZCR_STOP reason=signal")
        relay_service.stop()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        value = getattr(signal, name, None)
        if value is not None:
            try:
                signal.signal(value, stop_handler)
            except (OSError, ValueError):
                pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ZCode desktop HTTP relay")
    parser.add_argument("--config", required=True, help="private desktop-config.json")
    parser.add_argument("--mid", help="override device_mid without editing the config")
    parser.add_argument(
        "--delete-on-exit",
        action="store_true",
        help="delete this device registration on a clean non-KICKED exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )
    args = _parser().parse_args(argv)
    try:
        config = RelayConfig.load(args.config, mid=args.mid)
    except ConfigError:
        LOG.error("配置不可用或不符合固定 manual 模式")
        return 2
    relay = ZcodeRelay(config)
    _install_stop_handlers(relay)
    try:
        outcome = relay.run()
    except KeyboardInterrupt:
        relay.stop()
        outcome = "stopped"
    finally:
        relay.close(delete_device=args.delete_on_exit)
    LOG.info("ZCR_EXIT outcome=%s", outcome)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
