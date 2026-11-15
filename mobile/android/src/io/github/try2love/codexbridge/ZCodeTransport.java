package io.github.try2love.codexbridge;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.drafts.Draft_6455;
import org.java_websocket.handshake.ServerHandshake;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import javax.net.ssl.HttpsURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory HTTP-over-WebSocket transport for the ZCode remote terminal.
 * The class owns no Android objects. A disconnected socket can be reopened before
 * a new request is sent; requests already sent are never replayed.
 */
public class ZCodeTransport {
    public static final String REMOTE_ORIGIN = "https://zcode.z.ai";

    static final int MAX_REQUEST_BODY = 20 * 1024 * 1024;
    static final int MAX_RESPONSE_BODY = 20 * 1024 * 1024;
    static final long MAX_RESPONSE_BUDGET = 32L * 1024 * 1024;
    static final int MAX_WS_MESSAGE = 1024 * 1024;
    static final int CHUNK_SIZE = 49_152;
    private static final long CONNECT_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(20);
    private static final long REQUEST_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(75);
    private static final int MAX_REQUESTS = 16;
    private static final String VERSION = "3.18.2";
    private static final String TOKEN_URL = REMOTE_ORIGIN + "/api/v1/remote/token";
    private static final int MAX_TOKEN_RESPONSE = 1024 * 1024;
    private static final ResponseBudget RESPONSE_BUDGET = new ResponseBudget(MAX_RESPONSE_BUDGET);
    private static final Set<String> ALLOWED_REQUEST_HEADERS = new java.util.HashSet<>(java.util.Arrays.asList(
            "accept", "accept-encoding", "accept-language", "cache-control",
            "content-range", "content-type", "cookie", "etag", "if-match",
            "if-none-match", "if-range", "origin", "pragma", "range",
            "user-agent", "x-csrf-token"
    ));

    private final String sid;
    private final String mid;
    private volatile String accountJwt;
    private final Semaphore requestSlots = new Semaphore(MAX_REQUESTS, true);
    private final ConcurrentMap<String, Pending> pending = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler;
    private final Object connectLock = new Object();

    private volatile Session session;
    private volatile State state = State.NEW;
    private volatile boolean kicked;
    private volatile boolean closed;
    private volatile boolean authFailed;
    private volatile CountDownLatch authLatch = new CountDownLatch(1);
    private volatile ScheduledFuture<?> pairStatusTask;

    public ZCodeTransport(String jwt, String sid, String mid) {
        if (jwt == null || jwt.isEmpty()) {
            throw new IllegalArgumentException("jwt must not be empty");
        }
        if (sid == null || sid.isEmpty()) {
            throw new IllegalArgumentException("sid must not be empty");
        }
        if (mid == null || mid.isEmpty()) {
            throw new IllegalArgumentException("mid must not be empty");
        }
        this.sid = sid;
        this.mid = mid;
        this.accountJwt = jwt;
        scheduler = Executors.newSingleThreadScheduledExecutor(new DaemonThreadFactory("zcode-pair-status"));
    }

    /** Opens a fresh terminal token and waits for auth_ack within one 20 second deadline. */
    public void connect() throws IOException {
        synchronized (connectLock) {
            if (closed) {
                throw new IOException("ZCode transport is closed");
            }
            if (kicked) {
                throw new IOException("ZCode transport was rejected");
            }
            if (isConnected()) {
                return;
            }

            long deadline = System.nanoTime() + CONNECT_TIMEOUT_NANOS;
            cancelPairStatus();
            failAll("connection replaced");
            state = State.CONNECTING;
            authFailed = false;
            CountDownLatch latch = new CountDownLatch(1);
            authLatch = latch;
            session = null;
            Session candidate = null;
            try {
                String terminalToken = obtainTerminalToken(deadline);
                URI socketUri = URI.create("wss://zcode.z.ai/api/v1/remote/ws2?token="
                        + encode(terminalToken) + "&mid=" + encode(mid));
                candidate = new Session(socketUri);
                candidate.addHeader("Origin", REMOTE_ORIGIN);
                session = candidate;

                long remaining = remainingMillis(deadline);
                if (remaining <= 0 || !candidate.connectBlocking(remaining, TimeUnit.MILLISECONDS)) {
                    throw new IOException("ZCode connection timed out");
                }
                remaining = remainingMillis(deadline);
                if (remaining <= 0 || !latch.await(remaining, TimeUnit.MILLISECONDS)) {
                    throw new IOException("ZCode authentication timed out");
                }
                if (authFailed || state != State.READY) {
                    throw new IOException(kicked ? "ZCode connection was rejected" : "ZCode authentication failed");
                }
                startPairStatus(candidate);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                if (candidate != null) {
                    disconnect(candidate, false);
                } else {
                    state = State.DISCONNECTED;
                    authLatch.countDown();
                    failAll("connection interrupted");
                }
                throw new IOException("ZCode connection interrupted");
            } catch (IOException error) {
                if (candidate != null) {
                    disconnect(candidate, false);
                } else {
                    state = State.DISCONNECTED;
                    authLatch.countDown();
                    failAll("connection failed");
                }
                throw new IOException(error.getMessage());
            } catch (RuntimeException error) {
                if (candidate != null) {
                    disconnect(candidate, false);
                } else {
                    state = State.DISCONNECTED;
                    authLatch.countDown();
                    failAll("connection failed");
                }
                throw new IOException("ZCode connection failed");
            }
        }
    }

    /** Exchanges the account JWT for a short-lived terminal token. No retry is performed here. */
    private String obtainTerminalToken(long deadline) throws IOException {
        HttpsURLConnection connection = null;
        byte[] responseBytes = new byte[0];
        byte[] requestBytes = "{\"role\":\"terminal\"}".getBytes(StandardCharsets.UTF_8);
        try {
            connection = (HttpsURLConnection) new URL(TOKEN_URL).openConnection();
            int timeout = (int) Math.min(Integer.MAX_VALUE, remainingMillis(deadline));
            if (timeout <= 0) {
                throw new IOException("ZCode token request timed out");
            }
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setConnectTimeout(timeout);
            connection.setReadTimeout(timeout);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Authorization", "Bearer " + accountJwt);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");
            connection.setFixedLengthStreamingMode(requestBytes.length);
            connection.setDoOutput(true);
            try (java.io.OutputStream output = connection.getOutputStream()) {
                output.write(requestBytes);
            }
            int status = connection.getResponseCode();
            if (status != 200) {
                throw new IOException("ZCode terminal token request was rejected");
            }
            responseBytes = readLimited(connection.getInputStream(), MAX_TOKEN_RESPONSE);
            JSONObject root = new JSONObject(new String(responseBytes, StandardCharsets.UTF_8));
            if (root.has("code") && root.optInt("code", -1) != 0) {
                throw new IOException("ZCode terminal token response was rejected");
            }
            Object dataValue = root.opt("data");
            if (!(dataValue instanceof JSONObject)) {
                throw new IOException("ZCode terminal token response was invalid");
            }
            JSONObject data = (JSONObject) dataValue;
            String token = data.optString("token", "");
            int expiresIn = data.optInt("expires_in", -1);
            if (!token.matches("[A-Za-z0-9_-]{21}[AQgw]") || expiresIn <= 0) {
                throw new IOException("ZCode terminal token response was invalid");
            }
            return token;
        } catch (IOException | JSONException error) {
            throw new IOException("ZCode terminal token request failed");
        } finally {
            java.util.Arrays.fill(responseBytes, (byte) 0);
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static byte[] readLimited(InputStream input, int limit) throws IOException {
        try (InputStream stream = input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = stream.read(buffer)) != -1) {
                if (output.size() + (long) read > limit) {
                    throw new IOException("response is too large");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    public boolean isConnected() {
        Session current = session;
        return !closed && state == State.READY && current != null && current.isOpen();
    }

    /** True after a server KICKED error; this instance must not reconnect. */
    public boolean isKicked() {
        return kicked;
    }

    public void close() {
        Session current;
        synchronized (connectLock) {
            if (closed) {
                return;
            }
            closed = true;
            state = State.CLOSED;
            cancelPairStatus();
            authLatch.countDown();
            failAll("connection closed");
            current = session;
            session = null;
        }
        if (current != null) {
            current.close(1000, "client_close");
        }
        accountJwt = "";
        scheduler.shutdownNow();
    }

    public Response request(String method, String path, Map<String, List<String>> headers, byte[] body)
            throws IOException {
        String checkedMethod = checkedMethod(method);
        String checkedPath = checkedPath(path);
        byte[] checkedBody = body == null ? new byte[0] : body;
        if (checkedBody.length > MAX_REQUEST_BODY) {
            throw new IOException("request body is too large");
        }
        if (!"POST".equals(checkedMethod) && checkedBody.length != 0) {
            throw new IOException("GET and HEAD requests must not have a body");
        }
        Map<String, List<String>> safeHeaders = safeRequestHeaders(headers);
        if (!isConnected()) {
            connect();
        }

        long deadline = System.nanoTime() + REQUEST_TIMEOUT_NANOS;
        boolean acquired = false;
        try {
            acquired = requestSlots.tryAcquire(remainingMillis(deadline), TimeUnit.MILLISECONDS);
            if (!acquired) {
                throw new IOException("too many pending ZCode requests");
            }
            if (!isConnected()) {
                throw new IOException("ZCode transport is not connected");
            }

            String requestId = UUID.randomUUID().toString();
            Pending exchange = new Pending(requestId, RESPONSE_BUDGET);
            pending.put(requestId, exchange);
            try {
                JSONObject start = new JSONObject();
                start.put("zcode_type", "platform-request");
                start.put("requestId", requestId);
                start.put("bridgeHttp", 1);
                start.put("kind", "start");
                start.put("method", checkedMethod);
                start.put("path", checkedPath);
                start.put("headers", headersJson(safeHeaders));
                start.put("length", checkedBody.length);
                sendPayload(start, requestId);

                int sequence = 0;
                for (int offset = 0; offset < checkedBody.length; offset += CHUNK_SIZE) {
                    int length = Math.min(CHUNK_SIZE, checkedBody.length - offset);
                    byte[] chunk = new byte[length];
                    System.arraycopy(checkedBody, offset, chunk, 0, length);
                    JSONObject message = new JSONObject();
                    message.put("zcode_type", "platform-request");
                    message.put("requestId", requestId);
                    message.put("bridgeHttp", 1);
                    message.put("kind", "chunk");
                    message.put("seq", sequence++);
                    message.put("data", Base64.getEncoder().encodeToString(chunk));
                    sendPayload(message, requestId);
                }

                JSONObject end = new JSONObject();
                end.put("zcode_type", "platform-request");
                end.put("requestId", requestId);
                end.put("bridgeHttp", 1);
                end.put("kind", "end");
                end.put("seq", sequence);
                sendPayload(end, requestId);

                long remaining = remainingMillis(deadline);
                boolean receivedResponse = false;
                if (remaining > 0) {
                    try {
                        receivedResponse = exchange.done.await(remaining, TimeUnit.MILLISECONDS);
                    } catch (InterruptedException error) {
                        Response completed = exchange.onRequestTimeout();
                        Thread.currentThread().interrupt();
                        if (completed != null) {
                            return exchange.claimCompleted();
                        }
                        throw new IOException("ZCode request interrupted");
                    }
                }
                if (!receivedResponse) {
                    Response completed = exchange.onRequestTimeout();
                    if (completed != null) {
                        return exchange.claimCompleted();
                    }
                    throw new RequestTimeoutException("ZCode request timed out");
                }
                if (exchange.failure != null) {
                    if (exchange.unknown) {
                        throw new RequestUnknownException("ZCode request result is unknown");
                    }
                    throw new IOException(exchange.failure);
                }
                Response completed = exchange.claimCompleted();
                if (completed == null) {
                    throw new RequestUnknownException("ZCode response was not delivered");
                }
                return completed;
            } finally {
                try {
                    pending.remove(requestId, exchange);
                } finally {
                    exchange.abandonUnclaimed();
                }
            }
        } catch (JSONException error) {
            throw new IOException("invalid platform request");
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException("ZCode request interrupted");
        } finally {
            if (acquired) {
                requestSlots.release();
            }
        }
    }

    private void startPairStatus(final Session owner) {
        pairStatusTask = scheduler.scheduleAtFixedRate(() -> {
            if (owner != session || !isConnected() || kicked || closed) {
                return;
            }
            try {
                owner.send(envelope("pair_status_query").toString());
            } catch (Exception error) {
                disconnect(owner, false);
                try {
                    owner.close();
                } catch (RuntimeException ignored) {
                    // The connection is already unusable.
                }
            }
        }, 5, 5, TimeUnit.SECONDS);
    }

    private void cancelPairStatus() {
        ScheduledFuture<?> task = pairStatusTask;
        pairStatusTask = null;
        if (task != null) {
            task.cancel(false);
        }
    }

    private void sendPayload(JSONObject payload, String requestId) throws IOException {
        try {
            JSONObject message = envelope("data");
            message.put("payload", payload);
            send(message, requestId);
        } catch (JSONException error) {
            Pending exchange = pending.get(requestId);
            if (exchange != null) {
                exchange.fail("invalid platform request");
            }
            throw new IOException("invalid platform request");
        }
    }

    private void send(JSONObject message, String requestId) throws IOException {
        Session current = session;
        if (current == null || !current.isOpen()) {
            Pending exchange = pending.get(requestId);
            if (exchange != null) {
                exchange.failUnknown("connection closed");
            }
            throw new RequestUnknownException("ZCode connection closed while sending");
        }
        try {
            current.send(message.toString());
        } catch (RuntimeException error) {
            Pending exchange = pending.get(requestId);
            if (exchange != null) {
                exchange.failUnknown("connection closed");
            }
            throw new RequestUnknownException("ZCode connection closed while sending");
        }
    }

    private void onSessionMessage(Session owner, String message) {
        if (owner != session) {
            return;
        }
        if (message.getBytes(StandardCharsets.UTF_8).length > MAX_WS_MESSAGE) {
            protocolFailure(owner);
            return;
        }

        final JSONObject envelope;
        try {
            envelope = new JSONObject(message);
        } catch (JSONException error) {
            protocolFailure(owner);
            return;
        }

        String type = envelope.optString("type", "");
        if ("auth_ack".equals(type)) {
            if (state != State.CONNECTING || !sid.equals(envelope.optString("device_sid", ""))
                    || !validPairStatus(envelope.optString("pair_status", ""))) {
                protocolFailure(owner);
                return;
            }
            state = State.READY;
            authLatch.countDown();
            return;
        }
        if ("error".equals(type)) {
            boolean rejected = "KICKED".equals(envelope.optString("code", ""));
            kicked = kicked || rejected;
            authFailed = true;
            authLatch.countDown();
            state = rejected ? State.KICKED : State.DISCONNECTED;
            failAll(rejected ? "connection rejected" : "remote error");
            try {
                owner.close(1008, rejected ? "kicked" : "remote_error");
            } catch (RuntimeException ignored) {
                // Closing is best effort; no reconnect is attempted.
            }
            return;
        }
        if ("pair_status_ack".equals(type)) {
            if (state == State.READY && validPairStatus(envelope.optString("pair_status", ""))) {
                return;
            }
            protocolFailure(owner);
            return;
        }
        if (!"data".equals(type)) {
            return;
        }
        if (state != State.READY) {
            protocolFailure(owner);
            return;
        }
        Object payloadValue = envelope.opt("payload");
        if (!(payloadValue instanceof JSONObject)) {
            protocolFailure(owner);
            return;
        }
        JSONObject payload = (JSONObject) payloadValue;
        if (!"platform-response".equals(payload.optString("zcode_type", ""))) {
            return;
        }
        String requestId = payload.optString("requestId", "");
        Pending exchange = pending.get(requestId);
        if (exchange == null) {
            return;
        }
        try {
            exchange.accept(payload);
        } catch (IllegalArgumentException error) {
            exchange.failUnknown("invalid platform response");
        }
    }

    private static boolean validPairStatus(String status) {
        return "waiting".equals(status) || "matched".equals(status);
    }

    private void protocolFailure(Session owner) {
        authFailed = true;
        authLatch.countDown();
        disconnect(owner, false);
        try {
            owner.close(1002, "protocol_error");
        } catch (RuntimeException ignored) {
            // No retry or replay.
        }
    }

    private void disconnect(Session owner, boolean wasKicked) {
        if (owner != session) {
            return;
        }
        cancelPairStatus();
        kicked = kicked || wasKicked;
        if (!closed) {
            state = kicked ? State.KICKED : State.DISCONNECTED;
        }
        authFailed = true;
        authLatch.countDown();
        failAll("connection closed");
    }

    private void failAll(String reason) {
        for (Pending exchange : pending.values()) {
            exchange.failUnknown(reason);
        }
    }

    static Map<String, List<String>> safeRequestHeaders(Map<String, List<String>> headers)
            throws IOException {
        Map<String, List<String>> out = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (headers != null) {
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                String name = entry.getKey();
                String canonical = canonicalHeader(name);
                if (canonical == null) {
                    throw new IOException("request header is not allowed");
                }
                if (entry.getValue() == null) {
                    continue;
                }
                List<String> values = new ArrayList<>();
                for (String value : entry.getValue()) {
                    checkedHeaderValue(value);
                    values.add(value);
                }
                if (!values.isEmpty()) {
                    out.put(canonical, values);
                }
            }
        }
        out.put("Accept-Encoding", Collections.singletonList("identity"));
        return immutableHeaders(out);
    }

    private static String canonicalHeader(String name) throws IOException {
        if (!validHeaderName(name)) {
            throw new IOException("invalid request header name");
        }
        String lower = name.toLowerCase(Locale.US);
        if (!ALLOWED_REQUEST_HEADERS.contains(lower)) {
            throw new IOException("request header is not allowed");
        }
        switch (lower) {
            case "accept": return "Accept";
            case "accept-encoding": return "Accept-Encoding";
            case "accept-language": return "Accept-Language";
            case "cache-control": return "Cache-Control";
            case "content-range": return "Content-Range";
            case "content-type": return "Content-Type";
            case "cookie": return "Cookie";
            case "etag": return "ETag";
            case "if-match": return "If-Match";
            case "if-none-match": return "If-None-Match";
            case "if-range": return "If-Range";
            case "origin": return "Origin";
            case "pragma": return "Pragma";
            case "range": return "Range";
            case "user-agent": return "User-Agent";
            case "x-csrf-token": return "X-CSRF-Token";
            default: return null;
        }
    }

    private static JSONObject headersJson(Map<String, List<String>> headers) throws JSONException {
        JSONObject out = new JSONObject();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            List<String> values = entry.getValue();
            if (values.size() == 1) {
                out.put(entry.getKey(), values.get(0));
            } else {
                JSONArray array = new JSONArray();
                for (String value : values) {
                    array.put(value);
                }
                out.put(entry.getKey(), array);
            }
        }
        return out;
    }

    static boolean validHeaderName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (!(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z')
                    && !(c >= 'a' && c <= 'z') && "!#$%&'*+-.^_`|".indexOf(c) < 0) {
                return false;
            }
        }
        return true;
    }

    static void checkedHeaderValue(String value) throws IOException {
        if (value == null) {
            throw new IOException("invalid request header value");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\r' || c == '\n' || c == '\0') {
                throw new IOException("invalid request header value");
            }
        }
    }

    private static Map<String, List<String>> immutableHeaders(Map<String, List<String>> source) {
        Map<String, List<String>> out = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Map.Entry<String, List<String>> entry : source.entrySet()) {
            out.put(entry.getKey(), Collections.unmodifiableList(new ArrayList<>(entry.getValue())));
        }
        return Collections.unmodifiableMap(out);
    }

    private static Map<String, List<String>> responseHeaders(Object raw) {
        if (raw == null || raw == JSONObject.NULL) {
            return Collections.emptyMap();
        }
        if (!(raw instanceof JSONObject)) {
            throw new IllegalArgumentException("response headers must be an object");
        }
        JSONObject object = (JSONObject) raw;
        Map<String, List<String>> out = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Iterator<String> names = object.keys();
        while (names.hasNext()) {
            String name = names.next();
            if (!validHeaderName(name)) {
                throw new IllegalArgumentException("invalid response header name");
            }
            Object value = object.opt(name);
            List<String> values = new ArrayList<>();
            if (value instanceof String) {
                values.add((String) value);
            } else if (value instanceof JSONArray) {
                JSONArray array = (JSONArray) value;
                for (int i = 0; i < array.length(); i++) {
                    Object item = array.opt(i);
                    if (!(item instanceof String)) {
                        throw new IllegalArgumentException("invalid response header value");
                    }
                    values.add((String) item);
                }
            } else {
                throw new IllegalArgumentException("invalid response header value");
            }
            for (String text : values) {
                try {
                    checkedHeaderValue(text);
                } catch (IOException error) {
                    throw new IllegalArgumentException(error.getMessage());
                }
                List<String> existing = out.get(name);
                if (existing == null) {
                    existing = new ArrayList<>();
                    out.put(name, existing);
                }
                existing.add(text);
            }
        }
        return immutableHeaders(out);
    }

    private static String checkedMethod(String method) throws IOException {
        if (!"GET".equals(method) && !"HEAD".equals(method) && !"POST".equals(method)) {
            throw new IOException("HTTP method is not allowed");
        }
        return method;
    }

    static String checkedPath(String path) throws IOException {
        if (path == null || !path.startsWith("/") || path.startsWith("//")
                || path.indexOf('\\') >= 0 || path.indexOf('#') >= 0) {
            throw new IOException("invalid request path");
        }
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c <= 0x20 || c == 0x7f) {
                throw new IOException("invalid request path");
            }
        }
        return path;
    }

    private static String encode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (java.io.UnsupportedEncodingException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static long remainingMillis(long deadline) {
        long remaining = deadline - System.nanoTime();
        return remaining <= 0 ? 0 : Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining));
    }

    private static JSONObject envelope(String type) throws JSONException {
        JSONObject message = new JSONObject();
        message.put("type", type);
        message.put("client_ts", System.currentTimeMillis() / 1000L);
        return message;
    }

    private enum State { NEW, CONNECTING, READY, DISCONNECTED, KICKED, CLOSED }

    static final class ResponseBudget {
        private final long limit;
        private final AtomicLong reserved = new AtomicLong();

        ResponseBudget(long limit) {
            if (limit < 0) {
                throw new IllegalArgumentException("limit must not be negative");
            }
            this.limit = limit;
        }

        ResponseLease reserve(long length) {
            while (true) {
                long current = reserved.get();
                if (length < 0 || length > limit - current) {
                    return null;
                }
                if (reserved.compareAndSet(current, current + length)) {
                    return new ResponseLease(this, length);
                }
            }
        }

        long reservedBytes() {
            return reserved.get();
        }

        private void release(long length) {
            long remaining = reserved.addAndGet(-length);
            if (remaining < 0) {
                reserved.set(0);
            }
        }
    }

    private static final class ResponseLease implements Runnable {
        private final ResponseBudget budget;
        private final long length;
        private final AtomicBoolean released = new AtomicBoolean();

        ResponseLease(ResponseBudget budget, long length) {
            this.budget = budget;
            this.length = length;
        }

        @Override
        public void run() {
            if (released.compareAndSet(false, true)) {
                budget.release(length);
            }
        }
    }

    /** A response body is owned until close(); Gateway closes after writing it. */
    public static final class Response implements AutoCloseable {
        private final int status;
        private final Map<String, List<String>> headers;
        private final byte[] body;
        private final Runnable release;
        private final AtomicBoolean closed = new AtomicBoolean();

        public Response(int status, Map<String, List<String>> headers, byte[] body) {
            this(status, headers, body, null, false);
        }

        Response(int status, Map<String, List<String>> headers, byte[] body,
                Runnable release, boolean adopt) {
            this.status = status;
            this.headers = immutableHeaders(headers == null ? Collections.emptyMap() : headers);
            this.body = body == null ? new byte[0] : adopt ? body : body.clone();
            this.release = release;
        }

        public int status() { return status; }
        public Map<String, List<String>> headers() { return headers; }
        public byte[] body() { return body.clone(); }
        byte[] bodyBytes() { return body; }

        @Override
        public void close() {
            if (release != null && closed.compareAndSet(false, true)) {
                release.run();
            }
        }
    }

    /** Lets a local HTTP layer distinguish a definitive request timeout. */
    public static class RequestTimeoutException extends IOException {
        public RequestTimeoutException(String message) { super(message); }
    }

    /** The request may have reached Desktop, so callers must preserve an unknown result. */
    public static class RequestUnknownException extends IOException {
        public RequestUnknownException(String message) { super(message); }
    }

    private final class Session extends WebSocketClient {
        Session(URI uri) {
            super(uri, new Draft_6455());
        }

        @Override
        public void onOpen(ServerHandshake handshake) {
            try {
                JSONObject auth = envelope("auth_init");
                auth.put("device_sid", sid);
                JSONObject meta = new JSONObject();
                meta.put("platform", "web");
                meta.put("version", VERSION);
                auth.put("meta", meta);
                send(auth.toString());
            } catch (Exception error) {
                authFailed = true;
                authLatch.countDown();
                state = State.DISCONNECTED;
                failAll("authentication failed");
            }
        }

        @Override
        public void onMessage(String message) {
            onSessionMessage(this, message);
        }

        @Override
        public void onClose(int code, String reason, boolean remote) {
            disconnect(this, false);
        }

        @Override
        public void onError(Exception error) {
            if (this == session) {
                authFailed = true;
                authLatch.countDown();
                disconnect(this, false);
            }
        }

        @Override
        public String toString() {
            return "ZCodeTransportWebSocket";
        }
    }

    static final class Pending {
        private final String requestId;
        private final ResponseBudget budget;
        private final CountDownLatch done = new CountDownLatch(1);
        private final Map<String, List<String>> noHeaders = Collections.emptyMap();
        private byte[] body;
        private ResponseLease lease;
        private volatile Response response;
        private volatile String failure;
        private volatile boolean unknown;
        private boolean started;
        private boolean ended;
        private boolean claimed;
        private int nextSequence;
        private int received;
        private long expectedLength = -1;
        private int status;
        private Map<String, List<String>> headers = noHeaders;

        Pending(String requestId, ResponseBudget budget) {
            this.requestId = requestId;
            this.budget = budget;
        }

        synchronized void accept(JSONObject message) {
            if (ended || failure != null) {
                return;
            }
            if (!"platform-response".equals(message.optString("zcode_type"))) {
                throw new IllegalArgumentException("wrong response type");
            }
            if (!requestId.equals(message.optString("requestId"))) {
                throw new IllegalArgumentException("wrong request id");
            }
            if (message.optInt("bridgeHttp", -1) != 1) {
                throw new IllegalArgumentException("wrong bridge version");
            }
            String kind = message.optString("kind", "");
            if ("start".equals(kind)) {
                start(message);
            } else if ("chunk".equals(kind)) {
                chunk(message);
            } else if ("end".equals(kind)) {
                end(message);
            } else {
                throw new IllegalArgumentException("unknown response kind");
            }
        }

        private void start(JSONObject message) {
            if (started) {
                throw new IllegalArgumentException("duplicate response start");
            }
            int parsedStatus = message.optInt("status", -1);
            long parsedLength = message.optLong("length", -1);
            if (parsedStatus < 200 || parsedStatus > 599 || parsedLength < 0
                    || parsedLength > MAX_RESPONSE_BODY) {
                throw new IllegalArgumentException("invalid response start");
            }
            Map<String, List<String>> parsedHeaders = responseHeaders(message.opt("headers"));
            ResponseLease acquired = budget.reserve(parsedLength);
            if (acquired == null) {
                throw new IllegalArgumentException("response memory budget exceeded");
            }
            final byte[] allocated;
            try {
                allocated = new byte[(int) parsedLength];
            } catch (OutOfMemoryError error) {
                acquired.run();
                throw error;
            }
            status = parsedStatus;
            expectedLength = parsedLength;
            headers = parsedHeaders;
            body = allocated;
            lease = acquired;
            started = true;
        }

        private void chunk(JSONObject message) {
            if (!started || ended || body == null) {
                throw new IllegalArgumentException("response chunk before start");
            }
            int sequence = message.optInt("seq", -1);
            if (sequence != nextSequence) {
                throw new IllegalArgumentException("unexpected response sequence");
            }
            String data = message.optString("data", null);
            if (data == null) {
                throw new IllegalArgumentException("missing response data");
            }
            final byte[] decoded;
            try {
                decoded = Base64.getDecoder().decode(data);
            } catch (IllegalArgumentException error) {
                throw new IllegalArgumentException("invalid response base64");
            }
            if (decoded.length > CHUNK_SIZE || received + (long) decoded.length > expectedLength) {
                throw new IllegalArgumentException("response length exceeded");
            }
            System.arraycopy(decoded, 0, body, received, decoded.length);
            received += decoded.length;
            nextSequence++;
        }

        private void end(JSONObject message) {
            if (!started || ended || body == null) {
                throw new IllegalArgumentException("response end before start");
            }
            if (message.optInt("seq", -1) != nextSequence) {
                throw new IllegalArgumentException("invalid response end sequence");
            }
            if (received != expectedLength) {
                throw new IllegalArgumentException("response length mismatch");
            }
            ended = true;
            byte[] completedBody = body;
            ResponseLease completedLease = lease;
            body = null;
            lease = null;
            response = new Response(status, headers, completedBody, completedLease, true);
            done.countDown();
        }

        synchronized Response onRequestTimeout() {
            if (ended) {
                return response;
            }
            completeFailure("request timed out", true);
            return null;
        }

        synchronized Response claimCompleted() {
            if (!ended || response == null) {
                return null;
            }
            claimed = true;
            return response;
        }

        synchronized void abandonUnclaimed() {
            if (claimed) {
                return;
            }
            if (ended && response != null) {
                claimed = true;
                response.close();
                return;
            }
            completeFailure("request abandoned", true);
        }

        synchronized void fail(String reason) {
            completeFailure(reason, false);
        }

        synchronized void failUnknown(String reason) {
            completeFailure(reason, true);
        }

        private void completeFailure(String reason, boolean resultUnknown) {
            if (failure == null && !ended) {
                failure = reason;
                unknown = resultUnknown;
                body = null;
                received = 0;
                if (lease != null) {
                    lease.run();
                    lease = null;
                }
                done.countDown();
            }
        }
    }

    private static final class DaemonThreadFactory implements ThreadFactory {
        private final String name;

        DaemonThreadFactory(String name) { this.name = name; }

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, name);
            thread.setDaemon(true);
            return thread;
        }
    }
}
