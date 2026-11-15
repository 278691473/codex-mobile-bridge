package io.github.try2love.codexbridge;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.json.JSONObject;

public final class ZCodeTransportTests {
    private static int checks;

    public static void main(String[] args) throws Exception {
        int port = freePort();
        FakeTransport backend = new FakeTransport();
        ZCodeLocalGateway gateway = new ZCodeLocalGateway(backend, port);
        String origin = gateway.start();
        try {
            check(origin.equals("http://127.0.0.1:" + port), "stable loopback origin");
            check(gateway.isRunning(), "gateway running");
            String capability = gateway.capabilityCookie();
            check(capability.startsWith("localcap=") && capability.indexOf(';') < 0,
                    "capability cookie is a name=value pair");
            check(gateway.capabilityToken().length() == 32, "capability has 128 random bits");

            Response denied = send(origin, "GET", "/api/projects", Collections.emptyMap(),
                    Collections.emptyList(), false, null);
            check(denied.status == 403, "capability is required");
            checkJsonError(denied, 403, "gateway_http_403", "local capability required");
            check(backend.calls.get() == 0, "unauthorized request never reaches transport");

            String bootstrapUrl = gateway.bootstrapUrl();
            Response bootstrap = sendUrl(bootstrapUrl, null, null);
            check(bootstrap.status == 303, "bootstrap redirects");
            check("/".equals(bootstrap.header("Location")), "bootstrap returns to root");
            String setCookie = bootstrap.header("Set-Cookie");
            check(setCookie != null && setCookie.contains("HttpOnly")
                    && setCookie.contains("SameSite=Strict") && setCookie.startsWith(capability + ";"),
                    "bootstrap sets the HttpOnly local cookie");
            Response reusedBootstrap = sendUrl(bootstrapUrl, null, null);
            check(reusedBootstrap.status == 403, "consumed bootstrap path is invalid");
            String crossSiteUrl = gateway.bootstrapUrl();
            Response crossSiteBootstrap = sendUrl(crossSiteUrl, map("Sec-Fetch-Site", "cross-site"), null);
            check(crossSiteBootstrap.status == 403, "cross-site bootstrap rejected");
            check(sendUrl(crossSiteUrl, null, null).status == 303,
                    "rejected cross-site request does not consume bootstrap");
            String externalUrl = gateway.bootstrapUrl();
            Response externalBootstrap = sendUrl(externalUrl, map("Origin", "https://evil.example"), null);
            check(externalBootstrap.status == 403, "external bootstrap origin rejected");
            Response bootstrapCapAttempt = sendUrl(gateway.bootstrapUrl(),
                    map(ZCodeLocalGateway.CAP_HEADER, capability), null);
            check(bootstrapCapAttempt.status == 400, "client cannot set a capability through bootstrap");

            Map<String, String> browser = new LinkedHashMap<>();
            browser.put("Cookie", capability + "; desktop_session=alpha");
            browser.put("User-Agent", "Mozilla/5.0 (Linux; Android 15) Chrome/140.0 Mobile");
            browser.put("Accept", "text/html,application/xhtml+xml,image/avif,image/webp,*/*;q=0.8");
            browser.put("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.7");
            browser.put("Accept-Encoding", "gzip, deflate, br");
            browser.put("Cache-Control", "no-cache");
            browser.put("Sec-CH-UA", "\"Chromium\";v=\"140\"");
            browser.put("Sec-CH-UA-Mobile", "?1");
            browser.put("Sec-Fetch-Site", "same-origin");
            browser.put("Sec-Fetch-Mode", "no-cors");
            browser.put("Priority", "u=1, i");
            browser.put("Pragma", "no-cache");
            browser.put("If-Modified-Since", "Wed, 21 Oct 2015 07:28:00 GMT");
            browser.put("Referer", origin + "/");
            Response asset = send(origin, "GET", "/app.js?build=1", browser,
                    Collections.emptyList(), false, null);
            check(asset.status == 200, "real browser asset request accepted");
            check("asset-body".equals(asset.text()), "response body bytes preserved");
            FakeTransport.Capture capture = backend.last();
            check(origin.equals(capture.header("Origin")), "gateway injects local Origin");
            check("identity".equals(capture.header("Accept-Encoding")), "encoding forced to identity");
            check(capture.header("Referer") == null, "Referer dropped");
            check(capture.header("Cookie").equals("desktop_session=alpha"), "local cap never forwarded");
            check(capture.header("Sec-CH-UA") == null && capture.header("Priority") == null,
                    "unknown browser headers dropped");
            check("no-cache".equals(capture.header("Pragma")), "desktop Pragma header forwarded");
            check(capture.header("If-Modified-Since") == null,
                    "unsupported cache validation header dropped");
            check(asset.headers.containsKey("Set-Cookie")
                    && asset.headers.get("Set-Cookie").size() == 2, "multiple Set-Cookie preserved");
            check(!asset.headers.containsKey("X-Hop"), "Connection token hop header removed");
            check(!asset.headers.containsKey("Transfer-Encoding"), "Transfer-Encoding removed");

            Response probe = send(origin, "GET", "/api/projects",
                    map(ZCodeLocalGateway.CAP_HEADER, gateway.capabilityToken()), Collections.emptyList(), false, null);
            check(probe.status == 200, "capability header supports native probe: " + probe.status + " " + probe.text());

            Response noOrigin = send(origin, "POST", "/api/action",
                    map("Cookie", capability, "Content-Type", "application/octet-stream"),
                    Collections.singletonList(new byte[]{0, 1, 2, (byte) 255}), false, null);
            check(noOrigin.status == 403, "POST requires a trusted origin");
            Response nativePost = send(origin, "POST", "/api/action",
                    map("Cookie", capability, "Content-Type", "application/octet-stream",
                            ZCodeLocalGateway.NATIVE_ORIGIN_HEADER, ZCodeLocalGateway.NATIVE_ORIGIN),
                    Collections.singletonList(new byte[]{0, 1, 2, (byte) 255}), false, null);
            check(nativePost.status == 200, "native companion POST accepted");
            check(Arrays.equals(new byte[]{0, 1, 2, (byte) 255}, backend.last().body),
                    "POST body bytes preserved");
            Response sameOriginPost = send(origin, "POST", "/api/action",
                    map("Cookie", capability, "Content-Type", "application/json",
                            "X-CSRF-Token", "csrf-value"),
                    Collections.singletonList("{}".getBytes(StandardCharsets.UTF_8)), true, null);
            check(sameOriginPost.status == 200, "same-origin POST accepted");
            check("csrf-value".equals(backend.last().header("X-CSRF-Token")),
                    "CSRF header forwarded");

            Response head = send(origin, "HEAD", "/head",
                    map("Cookie", capability), Collections.emptyList(), false, null);
            check(head.status == 200, "HEAD accepted");
            check("123".equals(head.header("Content-Length")) && head.body.length == 0,
                    "HEAD preserves semantic Content-Length without a body");
        } finally {
            gateway.close();
            backend.close();
        }

        check(!gateway.isRunning(), "gateway close");
        localErrorResponseTests();
        occupiedPortFailsToStart();
        smugglingTests();
        memoryAndConcurrencyTests();
        responseBudgetTests();
        System.out.println("ZCODE_GATEWAY_PASS " + checks);
    }

    private static void localErrorResponseTests() throws Exception {
        int port = freePort();
        FakeTransport backend = new FakeTransport();
        ZCodeLocalGateway gateway = new ZCodeLocalGateway(backend, port);
        String origin = gateway.start();
        String capability = gateway.capabilityCookie();
        try {
            int before = backend.calls.get();
            Response unavailable = send(origin, "GET", "/transport-unavailable",
                    map("Cookie", capability), Collections.emptyList(), false, null);
            check(backend.calls.get() == before + 1, "transport failure is not retried");
            checkJsonError(unavailable, 502, "transport_unavailable",
                    "与电脑的连接已断开，请确认电脑端 Bridge 正在运行后重试");
            check(!unavailable.text().contains("fixture-secret"),
                    "transport exception text is not exposed");
            check(unavailable.header("X-ZCode-Result-Unknown") == null,
                    "definitive transport failure is not marked unknown");

            before = backend.calls.get();
            Response timeout = send(origin, "POST", "/transport-timeout",
                    map("Cookie", capability, "Content-Type", "application/json",
                            ZCodeLocalGateway.NATIVE_ORIGIN_HEADER, ZCodeLocalGateway.NATIVE_ORIGIN),
                    Collections.singletonList("{}".getBytes(StandardCharsets.UTF_8)), false, null);
            check(backend.calls.get() == before + 1, "timeout is not retried or replayed");
            checkJsonError(timeout, 504, "request_timeout",
                    "请求超时，操作结果未知，请先检查当前状态，确认后再重试");
            check("1".equals(timeout.header("X-ZCode-Result-Unknown")),
                    "timeout preserves unknown result header");
            check(!timeout.text().contains("fixture-secret"),
                    "timeout exception text is not exposed");

            before = backend.calls.get();
            Response unknown = send(origin, "POST", "/transport-unknown",
                    map("Cookie", capability, "Content-Type", "application/json",
                            ZCodeLocalGateway.NATIVE_ORIGIN_HEADER, ZCodeLocalGateway.NATIVE_ORIGIN),
                    Collections.singletonList("{}".getBytes(StandardCharsets.UTF_8)), false, null);
            check(backend.calls.get() == before + 1, "unknown write is not retried or replayed");
            checkJsonError(unknown, 502, "write_result_unknown",
                    "请求已发送，但未收到确认，操作结果未知，请先检查当前状态，确认后再重试");
            check("1".equals(unknown.header("X-ZCode-Result-Unknown")),
                    "unknown write preserves unknown result header");
            check(!unknown.text().contains("fixture-secret"),
                    "unknown exception text is not exposed");

            before = backend.calls.get();
            Response unavailableHead = send(origin, "HEAD", "/transport-unavailable",
                    map("Cookie", capability), Collections.emptyList(), false, null);
            check(backend.calls.get() == before + 1, "HEAD transport failure is not retried");
            check(unavailableHead.status == 502, "HEAD transport failure keeps status");
            check(unavailableHead.body.length == 0, "HEAD error response has no body");
            check(Integer.toString(unavailable.body.length).equals(unavailableHead.header("Content-Length")),
                    "HEAD error declares the equivalent JSON body length");
            checkErrorHeaders(unavailableHead);

            String specialMessage = "第一行 \"quote\"\n第二行\\结束";
            JSONObject escaped = new JSONObject(new String(
                    ZCodeLocalGateway.jsonError(specialMessage, "quoted_code"),
                    StandardCharsets.UTF_8));
            check(specialMessage.equals(escaped.getString("error")),
                    "JSON error round-trips quotes, newlines, and backslashes");
            check(escaped.length() == 2, "escaped JSON error keeps the public shape");
        } finally {
            gateway.close();
            backend.close();
        }
    }

    private static void responseBudgetTests() throws Exception {
        ZCodeTransport.ResponseBudget budget =
                new ZCodeTransport.ResponseBudget(ZCodeTransport.MAX_RESPONSE_BUDGET);
        List<ZCodeTransport.Pending> concurrent = new ArrayList<>();
        int twoMiB = 2 * 1024 * 1024;
        for (int i = 0; i < 16; i++) {
            ZCodeTransport.Pending pending = new ZCodeTransport.Pending("concurrent-" + i, budget);
            pending.accept(responseStart("concurrent-" + i, twoMiB));
            concurrent.add(pending);
        }
        check(budget.reservedBytes() == 32L * 1024 * 1024,
                "sixteen large responses reserve the full 32 MiB aggregate budget");
        boolean overBudgetRejected = false;
        try {
            ZCodeTransport.Pending rejected = new ZCodeTransport.Pending("over-budget", budget);
            rejected.accept(responseStart("over-budget", 1));
        } catch (IllegalArgumentException expected) {
            overBudgetRejected = true;
        }
        check(overBudgetRejected, "response above the 32 MiB aggregate budget is rejected before allocation");
        for (ZCodeTransport.Pending pending : concurrent) {
            pending.failUnknown("disconnect");
        }
        check(budget.reservedBytes() == 0, "disconnect releases every response reservation");

        boolean tooLargeRejected = false;
        try {
            ZCodeTransport.Pending tooLarge = new ZCodeTransport.Pending("too-large", budget);
            tooLarge.accept(responseStart("too-large", ZCodeTransport.MAX_RESPONSE_BODY + 1));
        } catch (IllegalArgumentException expected) {
            tooLargeRejected = true;
        }
        check(tooLargeRejected, "single response above 20 MiB is rejected");
        check(budget.reservedBytes() == 0, "single-response rejection allocates no budget");

        int length = 1024 * 1024 + 17;
        byte[] expected = new byte[length];
        for (int i = 0; i < expected.length; i++) {
            expected[i] = (byte) (i * 31);
        }
        ZCodeTransport.Pending completed = new ZCodeTransport.Pending("completed", budget);
        completed.accept(responseStart("completed", length));
        int sequence = 0;
        for (int offset = 0; offset < length; offset += ZCodeTransport.CHUNK_SIZE) {
            int size = Math.min(ZCodeTransport.CHUNK_SIZE, length - offset);
            byte[] chunk = Arrays.copyOfRange(expected, offset, offset + size);
            completed.accept(responseChunk("completed", sequence++, chunk));
        }
        completed.accept(responseEnd("completed", sequence));
        check(budget.reservedBytes() == length, "completed response transfers its reservation to Response");
        ZCodeTransport.Response response = completed.onRequestTimeout();
        check(response != null, "timeout observed after completion returns the completed response");
        check(completed.claimCompleted() == response, "completed response is handed off exactly once");
        completed.abandonUnclaimed();
        check(budget.reservedBytes() == length, "handed-off response is not released by request finally");
        check(Arrays.equals(expected, response.bodyBytes()), "preallocated response buffer is adopted exactly");
        byte[] defensive = response.body();
        defensive[0] ^= 0xff;
        check(response.bodyBytes()[0] == expected[0], "public body access remains defensively copied");
        completed.failUnknown("late disconnect");
        check(budget.reservedBytes() == length, "late disconnect does not release a completed response");
        response.close();
        response.close();
        check(budget.reservedBytes() == 0, "Response close is idempotent and releases completion budget");

        ZCodeTransport.Pending orphaned = new ZCodeTransport.Pending("orphaned", budget);
        orphaned.accept(responseStart("orphaned", 32));
        orphaned.accept(responseChunk("orphaned", 0, new byte[32]));
        orphaned.accept(responseEnd("orphaned", 1));
        check(budget.reservedBytes() == 32, "early completed response owns its reservation");
        orphaned.abandonUnclaimed();
        check(budget.reservedBytes() == 0,
                "completed response abandoned by a later send exception releases immediately");

        ZCodeTransport.Pending timedOut = new ZCodeTransport.Pending("timeout", budget);
        timedOut.accept(responseStart("timeout", 20 * 1024 * 1024));
        check(budget.reservedBytes() == 20L * 1024 * 1024, "incomplete response holds its reservation");
        check(timedOut.onRequestTimeout() == null, "incomplete response times out without a Response");
        check(budget.reservedBytes() == 0, "request timeout releases an incomplete response");
        timedOut.failUnknown("disconnect after timeout");
        check(budget.reservedBytes() == 0, "timeout and disconnect race cannot double-release");

        ZCodeTransport.Pending abandonedIncomplete = new ZCodeTransport.Pending("abandoned", budget);
        abandonedIncomplete.accept(responseStart("abandoned", 4096));
        check(budget.reservedBytes() == 4096, "unfinished response holds its reservation");
        abandonedIncomplete.abandonUnclaimed();
        check(budget.reservedBytes() == 0, "request exception releases an unfinished response");
    }

    private static JSONObject responseStart(String requestId, int length) throws Exception {
        JSONObject message = new JSONObject();
        message.put("zcode_type", "platform-response");
        message.put("requestId", requestId);
        message.put("bridgeHttp", 1);
        message.put("kind", "start");
        message.put("status", 200);
        message.put("length", length);
        message.put("headers", new JSONObject());
        return message;
    }

    private static JSONObject responseChunk(String requestId, int sequence, byte[] chunk) throws Exception {
        JSONObject message = new JSONObject();
        message.put("zcode_type", "platform-response");
        message.put("requestId", requestId);
        message.put("bridgeHttp", 1);
        message.put("kind", "chunk");
        message.put("seq", sequence);
        message.put("data", Base64.getEncoder().encodeToString(chunk));
        return message;
    }

    private static JSONObject responseEnd(String requestId, int sequence) throws Exception {
        JSONObject message = new JSONObject();
        message.put("zcode_type", "platform-response");
        message.put("requestId", requestId);
        message.put("bridgeHttp", 1);
        message.put("kind", "end");
        message.put("seq", sequence);
        return message;
    }

    private static void occupiedPortFailsToStart() throws Exception {
        int port = freePort();
        ServerSocket blocker = new ServerSocket(port, 1, InetAddress.getByName("127.0.0.1"));
        FakeTransport backend = new FakeTransport();
        ZCodeLocalGateway gateway = new ZCodeLocalGateway(backend, port);
        try {
            boolean failed = false;
            try {
                gateway.start();
            } catch (IOException expected) {
                failed = true;
            }
            check(failed, "occupied stable port fails instead of choosing another port");
        } finally {
            gateway.close();
            backend.close();
            blocker.close();
        }
    }

    private static void smugglingTests() throws Exception {
        int port = freePort();
        FakeTransport backend = new FakeTransport();
        ZCodeLocalGateway gateway = new ZCodeLocalGateway(backend, port);
        String origin = gateway.start();
        String cap = gateway.capabilityCookie();
        try {
            Response duplicateLength = raw(origin,
                    "POST /api/action HTTP/1.1\r\nHost: 127.0.0.1:" + port
                            + "\r\nOrigin: " + origin + "\r\nCookie: " + cap
                            + "\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n");
            check(duplicateLength.status == 400, "duplicate Content-Length rejected");
            Response transferEncoding = raw(origin,
                    "POST /api/action HTTP/1.1\r\nHost: 127.0.0.1:" + port
                            + "\r\nOrigin: " + origin + "\r\nCookie: " + cap
                            + "\r\nTransfer-Encoding: chunked\r\n\r\n");
            check(transferEncoding.status == 400, "Transfer-Encoding rejected");
            Response absolute = raw(origin,
                    "GET http://127.0.0.1:" + port + "/api/projects HTTP/1.1\r\nHost: 127.0.0.1:"
                            + port + "\r\nCookie: " + cap + "\r\n\r\n");
            check(absolute.status == 400, "absolute URL rejected");
            Response host = raw(origin,
                    "GET /api/projects HTTP/1.1\r\nHost: localhost:" + port
                            + "\r\nCookie: " + cap + "\r\n\r\n");
            check(host.status == 403, "Host mismatch rejected");
            check(backend.calls.get() == 0, "smuggling requests never reach transport");
        } finally {
            gateway.close();
            backend.close();
        }
    }

    private static void memoryAndConcurrencyTests() throws Exception {
        int port = freePort();
        FakeTransport backend = new FakeTransport();
        ZCodeLocalGateway gateway = new ZCodeLocalGateway(backend, port);
        String origin = gateway.start();
        String cap = gateway.capabilityCookie();
        try {
            Socket unauthorized = openHeaders(origin,
                    "POST /hold HTTP/1.1\r\nHost: 127.0.0.1:" + port
                            + "\r\nOrigin: " + origin + "\r\nContent-Length: 20971520\r\n\r\n");
            Response earlyDenied = readResponse(unauthorized);
            check(earlyDenied.status == 403, "unauthorized 20 MiB body rejected before allocation");
            unauthorized.close();

            backend.blockFor(10);
            List<Socket> bodySockets = new ArrayList<>();
            byte[] threeMiB = new byte[3 * 1024 * 1024];
            Arrays.fill(threeMiB, (byte) 7);
            for (int i = 0; i < 10; i++) {
                Socket socket = new Socket("127.0.0.1", port);
                writeHeaders(socket,
                        "POST /hold HTTP/1.1\r\nHost: 127.0.0.1:" + port
                                + "\r\nOrigin: " + origin + "\r\nCookie: " + cap
                                + "\r\nContent-Type: application/octet-stream\r\nContent-Length: "
                                + threeMiB.length + "\r\n\r\n");
                socket.getOutputStream().write(threeMiB);
                socket.getOutputStream().flush();
                bodySockets.add(socket);
            }
            check(backend.awaitEntered(10, 10_000), "ten body requests entered transport");
            Socket overBudget = openHeaders(origin,
                    "POST /hold HTTP/1.1\r\nHost: 127.0.0.1:" + port
                            + "\r\nOrigin: " + origin + "\r\nCookie: " + cap
                            + "\r\nContent-Length: 4194304\r\n\r\n");
            Response aggregate = readResponse(overBudget);
            check(aggregate.status == 503, "aggregate body reservation above 32 MiB returns 503");
            check(backend.calls.get() == 10, "over-budget body never reaches transport");
            overBudget.close();
            backend.release();
            for (Socket socket : bodySockets) {
                check(readResponse(socket).status == 200, "reserved body request completes");
                socket.close();
            }

            backend.blockFor(16);
            List<Socket> concurrent = new ArrayList<>();
            int before = backend.calls.get();
            for (int i = 0; i < 16; i++) {
                Socket socket = new Socket("127.0.0.1", port);
                writeHeaders(socket,
                        "GET /hold HTTP/1.1\r\nHost: 127.0.0.1:" + port
                                + "\r\nCookie: " + cap + "\r\n\r\n");
                concurrent.add(socket);
            }
            check(backend.awaitEntered(16, 10_000), "sixteen requests occupy the worker pool");
            Response overConcurrency = send(origin, "GET", "/api/projects",
                    map("Cookie", cap), Collections.emptyList(), false, null);
            check(overConcurrency.status == 503, "worker pool rejects request 17 with 503");
            check(backend.calls.get() == before + 16, "request 17 never reaches transport");
            backend.release();
            for (Socket socket : concurrent) {
                check(readResponse(socket).status == 200, "concurrent request completes");
                socket.close();
            }
        } finally {
            gateway.close();
            backend.close();
        }
    }

    private static Socket openHeaders(String origin, String request) throws IOException {
        URI uri = URI.create(origin);
        Socket socket = new Socket(uri.getHost(), uri.getPort());
        socket.setSoTimeout(5_000);
        socket.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
        socket.getOutputStream().flush();
        return socket;
    }

    private static void writeHeaders(Socket socket, String request) throws IOException {
        socket.setSoTimeout(10_000);
        socket.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
        socket.getOutputStream().flush();
    }

    private static Response raw(String origin, String request) throws IOException {
        URI uri = URI.create(origin);
        Socket socket = new Socket(uri.getHost(), uri.getPort());
        socket.setSoTimeout(5_000);
        socket.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
        socket.getOutputStream().flush();
        try {
            return readResponse(socket);
        } finally {
            socket.close();
        }
    }

    private static Response send(String origin, String method, String path, Map<String, String> headers,
            List<byte[]> bodyParts, boolean sameOrigin, String unused) throws IOException {
        Map<String, String> actual = new LinkedHashMap<>(headers);
        if (sameOrigin) {
            actual.put("Origin", origin);
        }
        byte[] body = join(bodyParts);
        return sendBytes(origin, method, path, actual, body);
    }

    private static Response sendUrl(String url, Map<String, String> headers, byte[] body) throws IOException {
        URI uri = URI.create(url);
        return sendBytes(uri.getScheme() + "://" + uri.getRawAuthority(), "GET", uri.getRawPath(),
                headers == null ? Collections.emptyMap() : headers, body == null ? new byte[0] : body);
    }

    private static Response sendBytes(String origin, String method, String path,
            Map<String, String> headers, byte[] body) throws IOException {
        URI uri = URI.create(origin);
        Socket socket = new Socket(uri.getHost(), uri.getPort());
        socket.setSoTimeout(10_000);
        StringBuilder head = new StringBuilder();
        head.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        head.append("Host: 127.0.0.1:").append(uri.getPort()).append("\r\n");
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            head.append(entry.getKey()).append(": ").append(entry.getValue()).append("\r\n");
        }
        if (body.length > 0 || "POST".equals(method)) {
            head.append("Content-Length: ").append(body.length).append("\r\n");
        }
        head.append("\r\n");
        socket.getOutputStream().write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        if (body.length > 0) {
            socket.getOutputStream().write(body);
        }
        socket.getOutputStream().flush();
        try {
            return readResponse(socket, "HEAD".equals(method));
        } finally {
            socket.close();
        }
    }

    private static byte[] join(List<byte[]> parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private static Response readResponse(Socket socket) throws IOException {
        return readResponse(socket, false);
    }

    private static Response readResponse(Socket socket, boolean head) throws IOException {
        InputStream input = socket.getInputStream();
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        int matched = 0;
        while (matched < 4) {
            int value = input.read();
            if (value == -1) {
                throw new IOException("incomplete response");
            }
            header.write(value);
            if (value == '\r') {
                matched = matched == 2 ? 3 : 1;
            } else if (value == '\n' && matched == 1) {
                matched = 2;
            } else if (value == '\n' && matched == 3) {
                matched = 4;
            } else {
                matched = 0;
            }
        }
        String text = new String(header.toByteArray(), StandardCharsets.ISO_8859_1);
        String[] lines = text.substring(0, text.length() - 4).split("\r\n", -1);
        int status = Integer.parseInt(lines[0].split(" ", 3)[1]);
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            String name = lines[i].substring(0, colon);
            String value = lines[i].substring(colon + 1).trim();
            List<String> values = headers.get(name);
            if (values == null) {
                values = new ArrayList<>();
                headers.put(name, values);
            }
            values.add(value);
        }
        String lengthHeader = first(headers, "Content-Length");
        int length = lengthHeader == null ? 0 : Integer.parseInt(lengthHeader);
        byte[] body = new byte[head ? 0 : length];
        int offset = 0;
        while (offset < body.length) {
            int count = input.read(body, offset, length - offset);
            if (count == -1) {
                throw new IOException("incomplete response body");
            }
            offset += count;
        }
        return new Response(status, headers, body);
    }

    private static String first(Map<String, List<String>> headers, String name) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue().get(0);
            }
        }
        return null;
    }

    private static Map<String, String> map(String... values) {
        Map<String, String> out = new LinkedHashMap<>();
        for (int i = 0; i < values.length; i += 2) {
            out.put(values[i], values[i + 1]);
        }
        return out;
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    private static void checkJsonError(Response response, int status, String code, String error)
            throws Exception {
        check(response.status == status, "JSON error keeps status: " + response.status);
        checkErrorHeaders(response);
        check(Integer.toString(response.body.length).equals(response.header("Content-Length")),
                "JSON error Content-Length matches body");
        JSONObject payload = new JSONObject(response.text());
        check(payload.length() == 2, "JSON error contains only error and code");
        check(error.equals(payload.getString("error")), "JSON error keeps stable message");
        check(code.equals(payload.getString("code")), "JSON error keeps stable code");
    }

    private static void checkErrorHeaders(Response response) {
        check(("application/json; charset=utf-8").equals(response.header("Content-Type")),
                "local error is JSON");
        check("no-store".equals(response.header("Cache-Control")), "local error is not cached");
        check("close".equals(response.header("Connection")), "local error closes the connection");
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static final class Response {
        final int status;
        final Map<String, List<String>> headers;
        final byte[] body;

        Response(int status, Map<String, List<String>> headers, byte[] body) {
            this.status = status;
            this.headers = headers;
            this.body = body;
        }

        String header(String name) {
            return first(headers, name);
        }

        String text() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    private static final class FakeTransport extends ZCodeTransport {
        final AtomicInteger calls = new AtomicInteger();
        final List<Capture> captures = Collections.synchronizedList(new ArrayList<Capture>());
        private volatile CountDownLatch entered = new CountDownLatch(0);
        private volatile CountDownLatch release = new CountDownLatch(0);

        FakeTransport() {
            super("jwt-is-not-used-by-test", "d_test", "mid_test");
        }

        @Override
        public Response request(String method, String path, Map<String, List<String>> headers, byte[] body)
                throws IOException {
            calls.incrementAndGet();
            captures.add(new Capture(method, path, headers,
                    "/hold".equals(path) ? new byte[0] : body));
            if ("/transport-unavailable".equals(path)) {
                throw new IOException("fixture-secret transport unavailable");
            }
            if ("/transport-timeout".equals(path)) {
                throw new RequestTimeoutException("fixture-secret timeout");
            }
            if ("/transport-unknown".equals(path)) {
                throw new RequestUnknownException("fixture-secret unknown");
            }
            entered.countDown();
            try {
                if (!release.await(10, TimeUnit.SECONDS)) {
                    throw new IOException("test release timeout");
                }
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IOException("test interrupted");
            }
            if ("/head".equals(path)) {
                Map<String, List<String>> values = new LinkedHashMap<>();
                values.put("Content-Length", Collections.singletonList("123"));
                return new Response(200, values, new byte[0]);
            }
            Map<String, List<String>> values = new LinkedHashMap<>();
            values.put("Connection", Arrays.asList("keep-alive", "X-Hop"));
            values.put("X-Hop", Collections.singletonList("remove-me"));
            values.put("Transfer-Encoding", Collections.singletonList("chunked"));
            values.put("Set-Cookie", Arrays.asList("one=1; Path=/", "two=2; Path=/"));
            return new Response(200, values, "asset-body".getBytes(StandardCharsets.UTF_8));
        }

        void blockFor(int count) {
            entered = new CountDownLatch(count);
            release = new CountDownLatch(1);
        }

        boolean awaitEntered(int count, long timeoutMillis) throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
            while (entered.getCount() > 0L && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            return entered.getCount() == 0L;
        }

        void release() {
            release.countDown();
        }

        Capture last() {
            synchronized (captures) {
                return captures.get(captures.size() - 1);
            }
        }

        static final class Capture {
            final String method;
            final String path;
            final Map<String, List<String>> headers;
            final byte[] body;

            Capture(String method, String path, Map<String, List<String>> headers, byte[] body) {
                this.method = method;
                this.path = path;
                this.headers = headers;
                this.body = body.clone();
            }

            String header(String name) {
                for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                    if (entry.getKey().equalsIgnoreCase(name)) {
                        return entry.getValue().isEmpty() ? null : entry.getValue().get(0);
                    }
                }
                return null;
            }
        }
    }
}
