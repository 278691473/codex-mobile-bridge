package io.github.try2love.codexbridge;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.json.JSONObject;

/**
 * A loopback-only HTTP/1.1 proxy used by the WebView and native App clients.
 * No request bytes or response bytes are modified except protocol framing.
 */
public final class ZCodeLocalGateway implements Closeable {
    public static final String CAP_COOKIE = "localcap";
    public static final String CAP_HEADER = "X-ZCode-Local-Cap";
    public static final String NATIVE_ORIGIN_HEADER = "X-ZCode-Native-Origin";
    public static final String NATIVE_ORIGIN = "zcode-mobile";

    private static final int MAX_HEADER = 32 * 1024;
    private static final int MAX_BODY = 20 * 1024 * 1024;
    private static final long MAX_RESERVED_BODIES = 32L * 1024 * 1024;
    private static final int SOCKET_TIMEOUT = 75_000;
    private static final String LOOPBACK = "127.0.0.1";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final ZCodeTransport transport;
    private final int requestedPort;
    private final Object lifecycle = new Object();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final java.util.concurrent.atomic.AtomicLong reservedBodies = new java.util.concurrent.atomic.AtomicLong();
    private final Set<Socket> activeSockets = Collections.synchronizedSet(new HashSet<Socket>());

    private volatile ServerSocket server;
    private volatile ThreadPoolExecutor workers;
    private volatile Thread acceptThread;
    private volatile String origin;
    private volatile String capabilityToken;
    private volatile String bootstrapPath;
    private volatile boolean started;

    public ZCodeLocalGateway(ZCodeTransport transport) {
        this(transport, 0);
    }

    /** A positive port is required by the App so 127.0.0.1:<port> stays stable. */
    public ZCodeLocalGateway(ZCodeTransport transport, int port) {
        if (transport == null) {
            throw new IllegalArgumentException("transport must not be null");
        }
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException("port must be between 1 and 65535");
        }
        this.transport = transport;
        this.requestedPort = port;
    }

    public String start() throws IOException {
        synchronized (lifecycle) {
            if (closed.get()) {
                throw new IOException("gateway is closed");
            }
            if (started) {
                return origin;
            }

            ServerSocket candidate = new ServerSocket();
            candidate.setReuseAddress(false);
            try {
                candidate.bind(new InetSocketAddress(InetAddress.getByName(LOOPBACK), requestedPort), 64);
            } catch (IOException error) {
                candidate.close();
                throw new IOException("cannot bind loopback port");
            }
            int port = candidate.getLocalPort();
            server = candidate;
            origin = "http://" + LOOPBACK + ":" + port;
            capabilityToken = randomHex(16);
            bootstrapPath = bootstrapPathValue();
            workers = new ThreadPoolExecutor(16, 16, 0, TimeUnit.MILLISECONDS,
                    new SynchronousQueue<Runnable>(), new GatewayThreadFactory(),
                    new ThreadPoolExecutor.AbortPolicy());
            started = true;
            Thread thread = new Thread(this::acceptLoop, "zcode-gateway-accept");
            thread.setDaemon(true);
            acceptThread = thread;
            thread.start();
            return origin;
        }
    }

    public String capabilityCookie() {
        ensureStarted();
        return CAP_COOKIE + "=" + capabilityToken;
    }

    public String capabilityToken() {
        ensureStarted();
        return capabilityToken;
    }

    /** Optional one-time bootstrap URL; the App may instead set capabilityCookie directly. */
    public String bootstrapUrl() {
        ensureStarted();
        synchronized (lifecycle) {
            bootstrapPath = bootstrapPathValue();
            return origin + bootstrapPath;
        }
    }

    public String origin() {
        ensureStarted();
        return origin;
    }

    public boolean isRunning() {
        return started && !closed.get();
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        started = false;
        ServerSocket currentServer = server;
        if (currentServer != null) {
            try {
                currentServer.close();
            } catch (IOException ignored) {
                // Closing the listener is best effort.
            }
        }
        Thread thread = acceptThread;
        if (thread != null) {
            thread.interrupt();
        }
        ThreadPoolExecutor pool = workers;
        if (pool != null) {
            pool.shutdownNow();
        }
        List<Socket> sockets;
        synchronized (activeSockets) {
            sockets = new ArrayList<>(activeSockets);
        }
        for (Socket active : sockets) {
            closeQuietly(active);
        }
        activeSockets.clear();
    }

    private void ensureStarted() {
        if (!started || origin == null || capabilityToken == null || closed.get()) {
            throw new IllegalStateException("gateway is not started");
        }
    }

    private void acceptLoop() {
        while (!closed.get()) {
            try {
                final Socket socket = server.accept();
                socket.setSoTimeout(SOCKET_TIMEOUT);
                socket.setTcpNoDelay(true);
                activeSockets.add(socket);
                try {
                    workers.execute(() -> handle(socket));
                } catch (RejectedExecutionException error) {
                    try {
                        writeError(socket, 503, "gateway concurrency limit reached", "GET");
                    } catch (IOException ignored) {
                        // The connection is already unusable.
                    } finally {
                        closeQuietly(socket);
                        activeSockets.remove(socket);
                    }
                }
            } catch (IOException error) {
                if (!closed.get()) {
                    continue;
                }
                return;
            }
        }
    }

    private void handle(Socket socket) {
        Request request = null;
        try {
            if (!socket.getInetAddress().isLoopbackAddress()) {
                return;
            }
            request = readRequestHead(socket);
            validateCommon(request);
            if (isBootstrap(request)) {
                bootstrap(socket, request);
                return;
            }
            validateCapability(request);
            validateWriteOrigin(request);
            if (!reserveBody(request.contentLength)) {
                throw new HttpError(503, "gateway body memory is busy");
            }
            try {
                request.body = readBody(request.input, request.contentLength);
                Map<String, List<String>> forwarded = forwardedHeaders(request);
                ZCodeTransport.Response response = null;
                try {
                    response = transport.request(request.method, request.target, forwarded, request.body);
                    writeUpstream(socket, request.method, response);
                } catch (ZCodeTransport.RequestTimeoutException timeout) {
                    writeUnknown(socket, 504, "request_timeout", request.method);
                    return;
                } catch (ZCodeTransport.RequestUnknownException unknown) {
                    writeUnknown(socket, 502, "write_result_unknown", request.method);
                    return;
                } catch (IOException unavailable) {
                    writeError(socket, 502, "与电脑的连接已断开，请确认电脑端 Bridge 正在运行后重试",
                            "transport_unavailable", request.method);
                    return;
                } finally {
                    if (response != null) {
                        response.close();
                    }
                }
            } finally {
                reservedBodies.addAndGet(-request.contentLength);
            }
        } catch (HttpError error) {
            try {
                writeError(socket, error.status, error.getMessage(),
                        request == null ? "GET" : request.method);
            } catch (IOException ignored) {
                // The peer may already have gone away.
            }
        } catch (Exception ignored) {
            try {
                writeError(socket, 502, "gateway request failed", "gateway_request_failed",
                        request == null ? "GET" : request.method);
            } catch (IOException alsoIgnored) {
                // The connection is already unusable.
            }
        } finally {
            closeQuietly(socket);
            activeSockets.remove(socket);
        }
    }

    private Request readRequestHead(Socket socket) throws IOException, HttpError {
        InputStream input = socket.getInputStream();
        ByteArrayOutputStream headerBytes = new ByteArrayOutputStream();
        int matched = 0;
        while (matched < 4) {
            int value = input.read();
            if (value == -1) {
                throw new HttpError(400, "incomplete request headers");
            }
            headerBytes.write(value);
            if (headerBytes.size() > MAX_HEADER) {
                throw new HttpError(431, "request headers are too large");
            }
            byte expected = matched == 0 || matched == 2 ? (byte) '\r'
                    : matched == 1 || matched == 3 ? (byte) '\n' : 0;
            matched = value == expected ? matched + 1 : (value == '\r' ? 1 : 0);
        }

        String text = new String(headerBytes.toByteArray(), StandardCharsets.ISO_8859_1);
        String[] lines = text.substring(0, text.length() - 4).split("\r\n", -1);
        if (lines.length == 0 || lines[0].isEmpty()) {
            throw new HttpError(400, "missing request line");
        }
        int first = lines[0].indexOf(' ');
        int second = first < 0 ? -1 : lines[0].indexOf(' ', first + 1);
        if (first <= 0 || second <= first + 1 || lines[0].indexOf(' ', second + 1) >= 0) {
            throw new HttpError(400, "invalid request line");
        }
        String method = lines[0].substring(0, first);
        String target = lines[0].substring(first + 1, second);
        String version = lines[0].substring(second + 1);
        if (!"HTTP/1.1".equals(version)) {
            throw new HttpError(505, "HTTP version is not supported");
        }
        if (!"GET".equals(method) && !"HEAD".equals(method) && !"POST".equals(method)) {
            throw new HttpError(405, "HTTP method is not allowed");
        }
        checkTarget(target);

        Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty() || line.charAt(0) == ' ' || line.charAt(0) == '\t') {
                throw new HttpError(400, "invalid request header folding");
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                throw new HttpError(400, "invalid request header");
            }
            String name = line.substring(0, colon);
            if (!ZCodeTransport.validHeaderName(name)) {
                throw new HttpError(400, "invalid request header name");
            }
            String value = trimOws(line.substring(colon + 1));
            checkHeaderValue(value);
            List<String> values = headers.get(name);
            if (values == null) {
                values = new ArrayList<>();
                headers.put(name, values);
            }
            values.add(value);
        }

        String host = single(headers, "Host", true);
        if (!("127.0.0.1:".concat(Integer.toString(server.getLocalPort()))).equals(host)) {
            throw new HttpError(403, "Host does not match gateway");
        }
        if (headers.containsKey("Transfer-Encoding")) {
            throw new HttpError(400, "Transfer-Encoding is not supported");
        }
        List<String> lengths = headers.get("Content-Length");
        if (lengths != null && lengths.size() != 1) {
            throw new HttpError(400, "duplicate Content-Length");
        }
        long length = 0;
        if (lengths != null) {
            String value = lengths.get(0);
            if (value.isEmpty() || !value.matches("[0-9]{1,10}")) {
                throw new HttpError(400, "invalid Content-Length");
            }
            try {
                length = Long.parseLong(value);
            } catch (NumberFormatException error) {
                throw new HttpError(400, "invalid Content-Length");
            }
        }
        if (length > MAX_BODY) {
            throw new HttpError(413, "request body is too large");
        }
        if (length > 0 && !"POST".equals(method)) {
            throw new HttpError(400, "GET and HEAD body is not supported");
        }
        if (headers.containsKey("Expect") || headers.containsKey("Upgrade")
                || headers.containsKey("Proxy-Connection")) {
            throw new HttpError(400, "request header is not supported");
        }
        return new Request(method, target, headers, input, (int) length);
    }

    private static byte[] readBody(InputStream input, int length) throws IOException, HttpError {
        if (length == 0) {
            return new byte[0];
        }
        byte[] body = new byte[length];
        int offset = 0;
        while (offset < length) {
            int count = input.read(body, offset, length - offset);
            if (count == -1) {
                throw new HttpError(400, "incomplete request body");
            }
            offset += count;
        }
        return body;
    }

    private void validateCommon(Request request) throws HttpError {
        String originValue = single(request.headers, "Origin", false);
        if (originValue != null && !origin.equals(originValue)) {
            throw new HttpError(403, "Origin does not match gateway");
        }
        String fetchSite = single(request.headers, "Sec-Fetch-Site", false);
        if ("cross-site".equalsIgnoreCase(fetchSite)) {
            throw new HttpError(403, "cross-site request rejected");
        }
        single(request.headers, "X-ZCode-Local-Cap", false);
        single(request.headers, NATIVE_ORIGIN_HEADER, false);
    }

    private synchronized boolean isBootstrap(Request request) {
        if (!"GET".equals(request.method) || bootstrapPath == null || !bootstrapPath.equals(request.target)) {
            return false;
        }
        bootstrapPath = null;
        return true;
    }

    private void bootstrap(Socket socket, Request request) throws IOException, HttpError {
        if (request.contentLength != 0 || request.headers.containsKey(CAP_HEADER)
                || request.headers.containsKey(NATIVE_ORIGIN_HEADER) || containsCapCookie(request.headers)) {
            throw new HttpError(400, "bootstrap request is invalid");
        }
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Set-Cookie", Collections.singletonList(
                CAP_COOKIE + "=" + capabilityToken + "; Path=/; HttpOnly; SameSite=Strict"));
        headers.put("Location", Collections.singletonList("/"));
        headers.put("Cache-Control", Collections.singletonList("no-store"));
        headers.put("Referrer-Policy", Collections.singletonList("no-referrer"));
        headers.put("Content-Security-Policy", Collections.singletonList("default-src 'none'"));
        writeResponse(socket, 303, headers, new byte[0], false);
    }

    private static boolean containsCapCookie(Map<String, List<String>> headers) {
        List<String> values = headers.get("Cookie");
        if (values == null) {
            return false;
        }
        for (String header : values) {
            for (String segment : header.split(";", -1)) {
                int equals = segment.indexOf('=');
                if (equals > 0 && CAP_COOKIE.equals(trimOws(segment.substring(0, equals)))) {
                    return true;
                }
            }
        }
        return false;
    }

    private void validateCapability(Request request) throws HttpError {
        String headerCap = single(request.headers, CAP_HEADER, false);
        if (headerCap != null && !secureEquals(headerCap, capabilityToken)) {
            throw new HttpError(403, "local capability rejected");
        }

        List<String> cookieHeaders = request.headers.get("Cookie");
        String cookieCap = null;
        int cookieCount = 0;
        if (cookieHeaders != null) {
            for (String header : cookieHeaders) {
                for (String segment : header.split(";", -1)) {
                    String item = trimOws(segment);
                    int equals = item.indexOf('=');
                    if (equals <= 0) {
                        continue;
                    }
                    if (CAP_COOKIE.equals(item.substring(0, equals))) {
                        cookieCount++;
                        cookieCap = item.substring(equals + 1);
                    }
                }
            }
        }
        if (cookieCount > 1) {
            throw new HttpError(403, "duplicate local capability");
        }
        if (cookieCap != null && !secureEquals(cookieCap, capabilityToken)) {
            throw new HttpError(403, "local capability rejected");
        }
        if (!secureEquals(headerCap, capabilityToken) && !secureEquals(cookieCap, capabilityToken)) {
            throw new HttpError(403, "local capability required");
        }
    }

    private void validateWriteOrigin(Request request) throws HttpError {
        if (!"POST".equals(request.method)) {
            return;
        }
        String requestOrigin = single(request.headers, "Origin", false);
        if (origin.equals(requestOrigin)) {
            return;
        }
        String nativeOrigin = single(request.headers, NATIVE_ORIGIN_HEADER, false);
        if (NATIVE_ORIGIN.equals(nativeOrigin)) {
            return;
        }
        throw new HttpError(403, "write origin rejected");
    }

    private Map<String, List<String>> forwardedHeaders(Request request) throws HttpError {
        Map<String, List<String>> filtered = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : request.headers.entrySet()) {
            String lower = entry.getKey().toLowerCase(Locale.US);
            if (lower.equals("accept-encoding") || !forwardedHeaderAllowed(lower)) {
                continue;
            }
            if (lower.equals("cookie")) {
                String stripped = stripCapCookie(entry.getValue());
                if (!stripped.isEmpty()) {
                    filtered.put("Cookie", Collections.singletonList(stripped));
                }
            } else {
                filtered.put(entry.getKey(), entry.getValue());
            }
        }
        filtered.put("Origin", Collections.singletonList(origin));
        try {
            return ZCodeTransport.safeRequestHeaders(filtered);
        } catch (IOException error) {
            throw new HttpError(400, "request header is not allowed");
        }
    }

    private static boolean forwardedHeaderAllowed(String lower) {
        return lower.equals("accept") || lower.equals("accept-language")
                || lower.equals("cache-control") || lower.equals("content-range")
                || lower.equals("content-type") || lower.equals("cookie")
                || lower.equals("etag") || lower.equals("if-match")
                || lower.equals("if-none-match") || lower.equals("if-range")
                || lower.equals("pragma") || lower.equals("range")
                || lower.equals("user-agent") || lower.equals("x-csrf-token");
    }

    private static String stripCapCookie(List<String> headers) {
        List<String> kept = new ArrayList<>();
        for (String header : headers) {
            for (String segment : header.split(";", -1)) {
                String item = trimOws(segment);
                if (item.isEmpty()) {
                    continue;
                }
                int equals = item.indexOf('=');
                String name = equals < 0 ? item : item.substring(0, equals);
                if (!CAP_COOKIE.equals(name)) {
                    kept.add(item);
                }
            }
        }
        StringBuilder out = new StringBuilder();
        for (String item : kept) {
            if (out.length() > 0) {
                out.append("; ");
            }
            out.append(item);
        }
        return out.toString();
    }

    private static String single(Map<String, List<String>> headers, String name, boolean required)
            throws HttpError {
        List<String> values = headers.get(name);
        if (values == null || values.isEmpty()) {
            if (required) {
                throw new HttpError(400, "missing " + name);
            }
            return null;
        }
        if (values.size() != 1) {
            throw new HttpError(400, "duplicate " + name);
        }
        return values.get(0);
    }

    private static boolean secureEquals(String first, String second) {
        if (first == null || second == null) {
            return false;
        }
        return MessageDigest.isEqual(first.getBytes(StandardCharsets.UTF_8),
                second.getBytes(StandardCharsets.UTF_8));
    }

    private static String trimOws(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && (value.charAt(start) == ' ' || value.charAt(start) == '\t')) {
            start++;
        }
        while (end > start && (value.charAt(end - 1) == ' ' || value.charAt(end - 1) == '\t')) {
            end--;
        }
        return value.substring(start, end);
    }

    private static void checkHeaderValue(String value) throws HttpError {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\r' || c == '\n' || c == '\0'
                    || (c < 0x20 && c != '\t') || c == 0x7f) {
                throw new HttpError(400, "invalid request header value");
            }
        }
    }

    private static void checkTarget(String target) throws HttpError {
        if (target == null || !target.startsWith("/") || target.startsWith("//")
                || target.indexOf('\\') >= 0 || target.indexOf('#') >= 0) {
            throw new HttpError(400, "invalid request target");
        }
        for (int i = 0; i < target.length(); i++) {
            char c = target.charAt(i);
            if (c <= 0x20 || c == 0x7f) {
                throw new HttpError(400, "invalid request target");
            }
        }
    }

    private void writeUpstream(Socket socket, String method, ZCodeTransport.Response response)
            throws IOException {
        if (response == null || response.status() < 200 || response.status() > 599) {
            writeError(socket, 502, "invalid ZCode response", method);
            return;
        }
        Map<String, List<String>> source = response.headers();
        Set<String> drop = new HashSet<>(Arrays.asList(
                "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection"));
        for (Map.Entry<String, List<String>> entry : source.entrySet()) {
            if (!ZCodeTransport.validHeaderName(entry.getKey())) {
                writeError(socket, 502, "invalid ZCode response", method);
                return;
            }
            if (entry.getValue() == null) {
                continue;
            }
            for (String value : entry.getValue()) {
                if (value == null || containsLineBreak(value)) {
                    writeError(socket, 502, "invalid ZCode response", method);
                    return;
                }
            }
            if ("connection".equalsIgnoreCase(entry.getKey())) {
                for (String value : entry.getValue()) {
                    for (String token : value.split(",", -1)) {
                        String normalized = trimOws(token).toLowerCase(Locale.US);
                        if (!normalized.isEmpty()) {
                            drop.add(normalized);
                        }
                    }
                }
            }
        }

        String upstreamLength = validContentLength(source);
        Map<String, List<String>> headers = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : source.entrySet()) {
            String lower = entry.getKey().toLowerCase(Locale.US);
            if (drop.contains(lower) || lower.equals("content-length")) {
                continue;
            }
            headers.put(entry.getKey(), new ArrayList<>(entry.getValue()));
        }

        byte[] body = response.bodyBytes();
        boolean noBodyStatus = response.status() == 204 || response.status() == 304;
        if ("HEAD".equals(method) || noBodyStatus) {
            if (upstreamLength != null) {
                headers.put("Content-Length", Collections.singletonList(upstreamLength));
            }
        } else {
            headers.put("Content-Length", Collections.singletonList(Integer.toString(body.length)));
        }
        headers.put("Connection", Collections.singletonList("close"));
        writeResponse(socket, response.status(), headers, "HEAD".equals(method) || noBodyStatus
                ? new byte[0] : body, "HEAD".equals(method));
    }

    private static String validContentLength(Map<String, List<String>> headers) throws IOException {
        List<String> values = headers.get("Content-Length");
        if (values == null) {
            return null;
        }
        String expected = null;
        for (String value : values) {
            if (value == null || !value.matches("[0-9]{1,10}")) {
                throw new IOException("invalid response Content-Length");
            }
            if (expected != null && !expected.equals(value)) {
                throw new IOException("conflicting response Content-Length");
            }
            expected = value;
        }
        return expected;
    }

    private static boolean containsLineBreak(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\r' || c == '\n' || c == '\0' || (c < 0x20 && c != '\t') || c == 0x7f) {
                return true;
            }
        }
        return false;
    }

    private void writeUnknown(Socket socket, int status, String code, String method) throws IOException {
        byte[] body = jsonError(errorMessage(code), code);
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Content-Type", Collections.singletonList("application/json; charset=utf-8"));
        headers.put("Cache-Control", Collections.singletonList("no-store"));
        headers.put("X-ZCode-Result-Unknown", Collections.singletonList("1"));
        headers.put("Content-Length", Collections.singletonList(Integer.toString(body.length)));
        headers.put("Connection", Collections.singletonList("close"));
        writeResponse(socket, status, headers, "HEAD".equals(method) ? new byte[0] : body,
                "HEAD".equals(method));
    }

    private void writeError(Socket socket, int status, String message, String method) throws IOException {
        writeError(socket, status, message, "gateway_http_" + status, method);
    }

    private void writeError(Socket socket, int status, String message, String code, String method)
            throws IOException {
        byte[] body = jsonError(message, code);
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Content-Type", Collections.singletonList("application/json; charset=utf-8"));
        headers.put("Cache-Control", Collections.singletonList("no-store"));
        headers.put("Content-Length", Collections.singletonList(Integer.toString(body.length)));
        if (status == 405) {
            headers.put("Allow", Collections.singletonList("GET, HEAD, POST"));
        }
        headers.put("Connection", Collections.singletonList("close"));
        writeResponse(socket, status, headers, "HEAD".equals(method) ? new byte[0] : body,
                "HEAD".equals(method));
    }

    private static String errorMessage(String code) {
        if ("request_timeout".equals(code)) {
            return "请求超时，操作结果未知，请先检查当前状态，确认后再重试";
        }
        return "请求已发送，但未收到确认，操作结果未知，请先检查当前状态，确认后再重试";
    }

    static byte[] jsonError(String message, String code) {
        String body = "{\"error\":" + JSONObject.quote(message)
                + ",\"code\":" + JSONObject.quote(code) + "}";
        return body.getBytes(StandardCharsets.UTF_8);
    }

    private static void writeResponse(Socket socket, int status, Map<String, List<String>> headers,
            byte[] body, boolean head) throws IOException {
        if (status < 200 || status > 599) {
            status = 500;
        }
        Map<String, List<String>> output = new LinkedHashMap<>();
        if (headers != null) {
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                if (!ZCodeTransport.validHeaderName(entry.getKey()) || entry.getValue() == null) {
                    throw new IOException("invalid response header");
                }
                List<String> values = new ArrayList<>();
                for (String value : entry.getValue()) {
                    if (value == null || containsLineBreak(value)) {
                        throw new IOException("invalid response header");
                    }
                    values.add(value);
                }
                output.put(entry.getKey(), values);
            }
        }
        int length = head ? contentLength(output) : body.length;
        output.put("Content-Length", Collections.singletonList(Integer.toString(length)));
        if (!output.containsKey("Connection")) {
            output.put("Connection", Collections.singletonList("close"));
        }

        OutputStream stream = socket.getOutputStream();
        StringBuilder prefix = new StringBuilder("HTTP/1.1 ");
        prefix.append(status).append(' ').append(reason(status)).append("\r\n");
        for (Map.Entry<String, List<String>> entry : output.entrySet()) {
            for (String value : entry.getValue()) {
                prefix.append(entry.getKey()).append(": ").append(value).append("\r\n");
            }
        }
        prefix.append("\r\n");
        stream.write(prefix.toString().getBytes(StandardCharsets.ISO_8859_1));
        if (!head) {
            stream.write(body);
        }
        stream.flush();
    }

    private static int contentLength(Map<String, List<String>> headers) {
        List<String> values = headers.get("Content-Length");
        if (values == null || values.size() != 1) {
            return 0;
        }
        try {
            return Integer.parseInt(values.get(0));
        } catch (NumberFormatException invalid) {
            return 0;
        }
    }

    private static String reason(int status) {
        switch (status) {
            case 200: return "OK";
            case 201: return "Created";
            case 202: return "Accepted";
            case 204: return "No Content";
            case 206: return "Partial Content";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 303: return "See Other";
            case 304: return "Not Modified";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 409: return "Conflict";
            case 413: return "Payload Too Large";
            case 416: return "Range Not Satisfiable";
            case 422: return "Unprocessable Content";
            case 429: return "Too Many Requests";
            case 431: return "Request Header Fields Too Large";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
            default: return "Response";
        }
    }

    private static String randomHex(int bytes) {
        byte[] values = new byte[bytes];
        RANDOM.nextBytes(values);
        char[] output = new char[bytes * 2];
        char[] alphabet = "0123456789abcdef".toCharArray();
        for (int i = 0; i < values.length; i++) {
            int value = values[i] & 0xff;
            output[i * 2] = alphabet[value >>> 4];
            output[i * 2 + 1] = alphabet[value & 15];
        }
        Arrays.fill(values, (byte) 0);
        return new String(output);
    }

    private static String bootstrapPathValue() {
        return "/__zcode_bootstrap__/" + randomHex(16);
    }

    private static void closeQuietly(Socket socket) {
        if (socket == null) {
            return;
        }
        try {
            socket.close();
        } catch (IOException ignored) {
            // The socket is already unusable.
        }
    }

    private boolean reserveBody(int length) {
        while (true) {
            long current = reservedBodies.get();
            if (current + length > MAX_RESERVED_BODIES) {
                return false;
            }
            if (reservedBodies.compareAndSet(current, current + length)) {
                return true;
            }
        }
    }

    private static final class Request {
        final String method;
        final String target;
        final Map<String, List<String>> headers;
        final InputStream input;
        final int contentLength;
        byte[] body = new byte[0];

        Request(String method, String target, Map<String, List<String>> headers,
                InputStream input, int contentLength) {
            this.method = method;
            this.target = target;
            this.headers = headers;
            this.input = input;
            this.contentLength = contentLength;
        }
    }

    private static final class HttpError extends Exception {
        final int status;

        HttpError(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    private static final class GatewayThreadFactory implements ThreadFactory {
        private final AtomicInteger sequence = new AtomicInteger();

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "zcode-gateway-" + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }
}
