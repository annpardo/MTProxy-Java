package io.github.example.jmtproxy;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.BindException;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class JMtProxy {
    private static final byte TRANSPORT_PADDED_INTERMEDIATE = (byte) 0xdd;
    private static final byte[] TRANSPORT_ABRIDGED = {(byte) 0xef};
    private static final byte[] TAG_ABRIDGED = {
            (byte) 0xef,
            (byte) 0xef,
            (byte) 0xef,
            (byte) 0xef
    };
    private static final byte[] TAG_INTERMEDIATE = {
            (byte) 0xee,
            (byte) 0xee,
            (byte) 0xee,
            (byte) 0xee
    };
    private static final byte[] TRANSPORT_HEADER = {
            TRANSPORT_PADDED_INTERMEDIATE,
            TRANSPORT_PADDED_INTERMEDIATE,
            TRANSPORT_PADDED_INTERMEDIATE,
            TRANSPORT_PADDED_INTERMEDIATE
    };
    private static final byte[] BACKEND_TRANSPORT_HEADER = TRANSPORT_HEADER;
    private static final byte[] TLS_SERVER_FIRST_PART = Hex.decode(
            "1603030000020000000303000000000000000000000000000000000000000000000000000000000000000000"
    );
    private static final byte[] TLS_SERVER_SECOND_PART = Hex.decode(
            "130100002e00330024001d00200000000000000000000000000000000000000000000000000000000000000000002b000203041403030001011703030000"
    );

    private static final int HANDSHAKE_SIZE = 64;
    private static final int BUFFER_SIZE = 32 * 1024;
    private static final int TLS_MAX_CHUNK_SIZE = 16 * 1024;
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b"
    );
    private static final List<String> PUBLIC_IPV4_ENDPOINTS = List.of(
            "https://api.ipify.org",
            "https://ifconfig.me/ip"
    );
    private static final List<String> PUBLIC_IPV6_ENDPOINTS = List.of(
            "https://api6.ipify.org",
            "https://ifconfig.me/ip"
    );
    private static final String TELEGRAM_PROXY_CONFIG_IPV4 = "https://core.telegram.org/getProxyConfig";
    private static final String TELEGRAM_PROXY_CONFIG_IPV6 = "https://core.telegram.org/getProxyConfigV6";
    private static final String TELEGRAM_PROXY_SECRET = "https://core.telegram.org/getProxySecret";
    private static final String BUILTIN_MIDDLE_PROXY_SECRET_HEX = "c4f9faca9678e6bb48ad6c7e2ce5c0d24430645d554addeb55419e034da62721d046eaab6e52ab14a95a443ecfb3463e79a05a66612adf9caeda8be9a80da6986fb0a6ff387af84d88ef3a6413713e5c3377f6e1a3d47d99f5e0c56eece8f05c54c490b079e31bef82ff0ee8f2b0a32756d249c5f21269816cb7061b265db212";
    private static final String BUILTIN_MIDDLE_PROXY_CONFIG_IPV4 = """
            # force_probability 10 10
            default 2;
            proxy_for 1 149.154.175.50:8888;
            proxy_for -1 149.154.175.50:8888;
            proxy_for 2 149.154.161.144:8888;
            proxy_for -2 149.154.161.184:8888;
            proxy_for 203 91.105.192.110:443;
            proxy_for -203 91.105.192.110:443;
            proxy_for 3 149.154.175.100:8888;
            proxy_for -3 149.154.175.100:8888;
            proxy_for 4 91.108.4.212:8888;
            proxy_for 4 91.108.4.139:8888;
            proxy_for 4 91.108.4.207:8888;
            proxy_for 4 91.108.4.152:8888;
            proxy_for 4 91.108.4.198:8888;
            proxy_for 4 91.108.4.161:8888;
            proxy_for 4 91.108.4.129:8888;
            proxy_for 4 91.108.4.180:8888;
            proxy_for 4 91.108.4.220:8888;
            proxy_for 4 91.108.4.203:8888;
            proxy_for -4 149.154.164.250:8888;
            proxy_for -4 149.154.165.109:8888;
            proxy_for 5 91.108.56.152:8888;
            proxy_for 5 91.108.56.117:8888;
            proxy_for -5 91.108.56.152:8888;
            proxy_for -5 91.108.56.117:8888;
            """;
    private static final String BUILTIN_MIDDLE_PROXY_CONFIG_IPV6 = """
            proxy_for 1 [2001:0b28:f23d:f001:0000:0000:0000:000d]:8888;
            proxy_for -1 [2001:0b28:f23d:f001:0000:0000:0000:000d]:8888;
            proxy_for 2 [2001:067c:04e8:f002:0000:0000:0000:000d]:80;
            proxy_for -2 [2001:067c:04e8:f002:0000:0000:0000:000d]:80;
            proxy_for 3 [2001:0b28:f23d:f003:0000:0000:0000:000d]:8888;
            proxy_for -3 [2001:0b28:f23d:f003:0000:0000:0000:000d]:8888;
            proxy_for 4 [2001:067c:04e8:f004:0000:0000:0000:000d]:8888;
            proxy_for -4 [2001:067c:04e8:f004:0000:0000:0000:000d]:8888;
            proxy_for 5 [2001:0b28:f23f:f005:0000:0000:0000:000d]:8888;
            proxy_for -5 [2001:0b28:f23f:f005:0000:0000:0000:000d]:8888;
            """;
    private static final Pattern PROXY_FOR_PATTERN = Pattern.compile("^\\s*proxy_for\\s+(-?\\d+)\\s+(\\S+?)\\s*;\\s*$");
    private static final int RPC_FLAG_NOT_ENCRYPTED = 0x00000002;
    private static final int RPC_FLAG_HAS_AD_TAG = 0x00000008;
    private static final int RPC_FLAG_MAGIC = 0x00001000;
    private static final int RPC_FLAG_EXTMODE2 = 0x00020000;
    private static final int RPC_FLAG_PAD = 0x08000000;
    private static final int RPC_FLAG_INTERMEDIATE = 0x20000000;
    private static final int RPC_FLAG_ABRIDGED = 0x40000000;
    private static final int RPC_FLAG_QUICKACK = 0x80000000;
    private static final int RPC_NONCE = 0x7acb87aa;
    private static final int RPC_HANDSHAKE = 0x7682eef5;
    private static final int RPC_HANDSHAKE_ERROR = 0x6a27beda;
    private static final int RPC_PROXY_REQ = 0x36cef1ee;
    private static final int RPC_PROXY_ANS = 0x4403da0d;
    private static final int RPC_CLOSE_CONN = 0x1fcf425d;
    private static final int RPC_CLOSE_EXT = 0x5eb634a2;
    private static final int RPC_SIMPLE_ACK = 0x3bac409b;
    private static final int RPC_PING = 0x5730a2df;
    private static final int RPC_PONG = 0x8430eaa7;
    private static final int RPC_CRYPTO_AES = 1;
    private static final int TL_PROXY_TAG = 0xdb1e26ae;
    private static final byte[] MIDDLE_PADDING_FILLER = {0x04, 0x00, 0x00, 0x00};

    private static int littleEndianInt(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff)
                | ((bytes[offset + 1] & 0xff) << 8)
                | ((bytes[offset + 2] & 0xff) << 16)
                | ((bytes[offset + 3] & 0xff) << 24);
    }

    private static void writeLittleEndianInt(OutputStream out, int value) throws IOException {
        out.write(value & 0xff);
        out.write((value >>> 8) & 0xff);
        out.write((value >>> 16) & 0xff);
        out.write((value >>> 24) & 0xff);
    }

    private static void writeLittleEndianLong(OutputStream out, long value) throws IOException {
        for (int i = 0; i < 8; i++) {
            out.write((int) ((value >>> (i * 8)) & 0xff));
        }
    }

    private static void writeLittleEndianShort(OutputStream out, int value) throws IOException {
        out.write(value & 0xff);
        out.write((value >>> 8) & 0xff);
    }

    private static byte[] littleEndianIntBytes(int value) {
        return new byte[]{
                (byte) value,
                (byte) (value >>> 8),
                (byte) (value >>> 16),
                (byte) (value >>> 24)
        };
    }

    private static byte[] littleEndianShortBytes(int value) {
        return new byte[]{
                (byte) value,
                (byte) (value >>> 8)
        };
    }

    private static byte[] reverseCopy(byte[] input) {
        byte[] out = input.clone();
        for (int i = 0, j = out.length - 1; i < j; i++, j--) {
            byte tmp = out[i];
            out[i] = out[j];
            out[j] = tmp;
        }
        return out;
    }

    private static byte[] reverseAll(byte[] input) {
        byte[] out = input.clone();
        for (int i = 0, j = out.length - 1; i < j; i++, j--) {
            byte tmp = out[i];
            out[i] = out[j];
            out[j] = tmp;
        }
        return out;
    }

    private static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static byte[] concat(byte[]... parts) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part);
        }
        return out.toByteArray();
    }

    private static boolean startsWith(byte[] bytes, byte[] prefix) {
        if (bytes.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (bytes[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static final Set<String> OPTION_NAMES = Set.of(
            "help",
            "generate-secret",
            "config",
            "secret",
            "port",
            "connect-timeout",
            "tls-domain",
            "classic",
            "secure",
            "tls",
            "ad-tag",
            "log-accepted",
            "log-rejected"
    );

    private JMtProxy() {
    }

    public static void main(String[] args) throws Exception {
        Config config = Config.parse(args);
        if (config.generateSecretOnly()) {
            byte[] secret = new byte[16];
            new SecureRandom().nextBytes(secret);
            System.out.println("Raw secret: " + Hex.encode(secret));
            System.out.println("MTProxy dd secret: dd" + Hex.encode(secret));
            return;
        }

        try (MtProxyServer server = new MtProxyServer(config)) {
            server.start();
        }
    }

    static final class MtProxyServer implements AutoCloseable {
        private final Config config;
        private final ExecutorService executor;
        private final Dc203Updater dc203Updater;
        private final List<ServerSocket> serverSockets = Collections.synchronizedList(new ArrayList<>());
        private final AtomicBoolean closed = new AtomicBoolean();

        MtProxyServer(Config config) {
            this.config = Objects.requireNonNull(config, "config");
            this.executor = Executors.newCachedThreadPool(new NamedThreadFactory("jmtproxy"));
            this.dc203Updater = new Dc203Updater(config.dcMaps());
        }

        void start() throws IOException {
            dc203Updater.start();
            List<ServerSocket> sockets = bindSockets();
            if (sockets.isEmpty()) {
                throw new BindException("no IPv4 or IPv6 listener could be started");
            }

            printStartupSummary();
            startStopCommandListener();
            Runtime.getRuntime().addShutdownHook(new Thread(() -> closeQuietly(this), "jmtproxy-shutdown"));

            try {
                for (int i = 1; i < sockets.size(); i++) {
                    ServerSocket socket = sockets.get(i);
                    executor.execute(() -> acceptLoop(socket));
                }
                acceptLoop(sockets.get(0));
            } finally {
                for (ServerSocket socket : sockets) {
                    closeQuietly(socket);
                }
                executor.shutdownNow();
            }
        }

        private void startStopCommandListener() {
            Thread thread = new Thread(() -> {
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
                while (!closed.get()) {
                    String line;
                    try {
                        line = reader.readLine();
                    } catch (IOException e) {
                        return;
                    }
                    if (line == null) {
                        return;
                    }
                    String command = line.trim().toLowerCase(Locale.ROOT);
                    if (command.equals("stop") || command.equals("shutdown") || command.equals("exit") || command.equals("quit")) {
                        closeQuietly(this);
                        return;
                    }
                }
            }, "jmtproxy-stdin-stop");
            thread.setDaemon(true);
            thread.start();
        }

        private void printStartupSummary() {
            System.out.println("========================================");
            System.out.println("Java MTProxy：运行中");
            System.out.println("服务器IPV4/IPV6：" + publicHostSummary());
            System.out.println("服务端口：" + config.listenPort());
            System.out.println("MTProxy Secret：" + Hex.encode(config.secret()));
            if (config.adTag() != null) {
                System.out.println("AD_TAG：已启用");
            }
            for (PublicHost publicHost : config.publicHosts()) {
                String label = publicHost.family().linkLabel().toUpperCase(Locale.ROOT);
                for (ProxyMode mode : config.modes().enabledModes()) {
                    System.out.println("TG " + label + "链接：tg://proxy?server=" + publicHost.host()
                            + "&port=" + config.listenPort()
                            + "&secret=" + config.publicSecret(mode));
                }
            }
            System.out.println("========================================");
        }

        private String publicHostSummary() {
            String ipv4 = "";
            String ipv6 = "";
            for (PublicHost publicHost : config.publicHosts()) {
                if (publicHost.family() == IpFamily.IPV4) {
                    ipv4 = publicHost.host();
                } else if (publicHost.family() == IpFamily.IPV6) {
                    ipv6 = publicHost.host();
                }
            }
            if (!ipv4.isBlank() && !ipv6.isBlank()) {
                return ipv4 + " / " + ipv6;
            }
            if (!ipv4.isBlank()) {
                return ipv4;
            }
            if (!ipv6.isBlank()) {
                return ipv6;
            }
            return config.publicHosts().stream().map(PublicHost::host).findFirst().orElse("unknown");
        }

        private List<ServerSocket> bindSockets() {
            List<ServerSocket> sockets = new ArrayList<>();
            for (String bindHost : bindHosts()) {
                try {
                    ServerSocket socket = new ServerSocket();
                    bind(socket, bindHost);
                    sockets.add(socket);
                    serverSockets.add(socket);
                } catch (IOException e) {
                    // Try the next address family; startup fails later if no listener was created.
                }
            }
            return sockets;
        }

        private List<String> bindHosts() {
            Set<IpFamily> families = config.publicHosts().stream()
                    .map(PublicHost::family)
                    .collect(java.util.stream.Collectors.toSet());
            if (families.contains(IpFamily.IPV4) && families.contains(IpFamily.IPV6)) {
                return List.of("::", "0.0.0.0");
            }
            if (families.contains(IpFamily.IPV6)) {
                return List.of("::");
            }
            return List.of("0.0.0.0");
        }

        private String bind(ServerSocket socket, String bindHost) throws IOException {
            try {
                socket.bind(new InetSocketAddress(bindHost, config.listenPort()));
                return bindHost;
            } catch (BindException e) {
                if (isWildcard(bindHost)) {
                    throw e;
                }
                socket.bind(new InetSocketAddress("0.0.0.0", config.listenPort()));
                return "0.0.0.0";
            }
        }

        private static boolean isWildcard(String host) {
            return host == null || host.isBlank() || host.equals("0.0.0.0") || host.equals("::");
        }

        private void acceptLoop(ServerSocket socket) {
            while (!socket.isClosed()) {
                try {
                    Socket client = socket.accept();
                    client.setTcpNoDelay(true);
                    executor.execute(new ProxyConnection(client, config));
                } catch (IOException e) {
                    if (!socket.isClosed()) {
                        log("accept failed on " + socket.getLocalSocketAddress() + ": " + e.getMessage());
                    }
                    break;
                }
            }
        }

        @Override
        public void close() throws IOException {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            synchronized (serverSockets) {
                for (ServerSocket socket : serverSockets) {
                    socket.close();
                }
            }
            dc203Updater.close();
            executor.shutdownNow();
        }

        private static void closeQuietly(ServerSocket socket) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }

        private static void closeQuietly(AutoCloseable closeable) {
            try {
                closeable.close();
            } catch (Exception ignored) {
            }
        }
    }

    static final class Dc203Updater implements AutoCloseable {
        private final DcMaps dcMaps;
        private final ScheduledExecutorService scheduler;

        Dc203Updater(DcMaps dcMaps) {
            this.dcMaps = dcMaps;
            this.scheduler = Executors.newSingleThreadScheduledExecutor(new NamedThreadFactory("jmtproxy-dc203"));
        }

        void start() {
            scheduler.execute(this::refreshQuietly);
            scheduler.scheduleWithFixedDelay(this::refreshQuietly, 1, 1, TimeUnit.HOURS);
        }

        private void refreshQuietly() {
            try {
                List<Endpoint> v4 = fetchDc203(TELEGRAM_PROXY_CONFIG_IPV4, IpFamily.IPV4);
                List<Endpoint> v6 = fetchDc203(TELEGRAM_PROXY_CONFIG_IPV6, IpFamily.IPV6);
                if (!v4.isEmpty()) {
                    dcMaps.replaceDynamic(203, IpFamily.IPV4, v4);
                }
                if (!v6.isEmpty()) {
                    dcMaps.replaceDynamic(203, IpFamily.IPV6, v6);
                }
            } catch (RuntimeException e) {
                // DC203 updates are optional; keep the built-in static DC203 on failure.
            }
        }

        private static List<Endpoint> fetchDc203(String url, IpFamily family) {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(15))
                    .version(HttpClient.Version.HTTP_1_1)
                    .build();
            try {
                HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                        .timeout(Duration.ofSeconds(20))
                        .header("User-Agent", "jmtproxy/0.1")
                        .GET()
                        .build();
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    return List.of();
                }
                return parseDc203Config(response.body(), family);
            } catch (IOException | InterruptedException | RuntimeException e) {
                if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                return List.of();
            }
        }

        static List<Endpoint> parseDc203Config(String body, IpFamily family) {
            List<Endpoint> endpoints = new ArrayList<>();
            if (body == null || body.isBlank()) {
                return endpoints;
            }
            for (String line : body.split("\\R")) {
                Matcher matcher = PROXY_FOR_PATTERN.matcher(line);
                if (!matcher.matches()) {
                    continue;
                }
                int dc;
                try {
                    dc = Integer.parseInt(matcher.group(1));
                } catch (NumberFormatException e) {
                    continue;
                }
                if (Math.abs(dc) != 203) {
                    continue;
                }
                Endpoint endpoint;
                try {
                    endpoint = parseEndpoint(matcher.group(2));
                } catch (IllegalArgumentException e) {
                    continue;
                }
                if (family == IpFamily.IPV4 && !Config.isIpv4(endpoint.host())) {
                    continue;
                }
                if (family == IpFamily.IPV6 && !Config.isIpv6(endpoint.host())) {
                    continue;
                }
                if (!endpoints.contains(endpoint)) {
                    endpoints.add(endpoint);
                }
            }
            return List.copyOf(endpoints);
        }

        static Endpoint parseEndpoint(String value) {
            String endpoint = value.trim();
            if (endpoint.endsWith(";")) {
                endpoint = endpoint.substring(0, endpoint.length() - 1);
            }
            String host;
            String portText;
            if (endpoint.startsWith("[")) {
                int close = endpoint.indexOf(']');
                if (close < 0 || close + 2 > endpoint.length() || endpoint.charAt(close + 1) != ':') {
                    throw new IllegalArgumentException("invalid endpoint: " + value);
                }
                host = endpoint.substring(1, close);
                portText = endpoint.substring(close + 2);
            } else {
                int colon = endpoint.lastIndexOf(':');
                if (colon <= 0 || colon == endpoint.length() - 1) {
                    throw new IllegalArgumentException("invalid endpoint: " + value);
                }
                host = endpoint.substring(0, colon);
                portText = endpoint.substring(colon + 1);
            }
            int port = Config.parseInt(portText, "dc port");
            if (port < 1 || port > 65535 || (!Config.isIpv4(host) && !Config.isIpv6(host))) {
                throw new IllegalArgumentException("invalid endpoint: " + value);
            }
            return new Endpoint(host, port);
        }

        @Override
        public void close() {
            scheduler.shutdownNow();
        }
    }

    static final class ProxyConnection implements Runnable {
        private final Socket client;
        private final Config config;

        ProxyConnection(Socket client, Config config) {
            this.client = client;
            this.config = config;
        }

        @Override
        public void run() {
            String peer = String.valueOf(client.getRemoteSocketAddress());
            try (Socket clientSocket = client) {
                ClientStreams clientStreams = FakeTls.tryAccept(
                        clientSocket.getInputStream(),
                        clientSocket.getOutputStream(),
                        config.secret(),
                        config.tlsDomain(),
                        config.modes().tls()
                );
                Handshake handshake = Handshake.read(clientStreams.input(), config.secret(), config.modes(), clientStreams.fakeTls());
                int backendDc = handshake.backendDc();
                IpFamily clientFamily = clientFamily(clientSocket);
                if (config.adTag() != null) {
                    List<Endpoint> endpoints = config.middleProxyState().endpoints(backendDc, clientFamily);
                    if (endpoints.isEmpty()) {
                        throw new IOException("unsupported middle proxy dc " + handshake.dcId());
                    }
                    try (ConnectedMiddleProxy connectedMiddle = connectMiddleProxy(
                            endpoints,
                            config.connectTimeoutMillis(),
                            backendDc,
                            handshake.transport(),
                            clientSocket,
                            config.adTag(),
                            config.middleProxyState().secret(),
                            config.publicHosts()
                    )) {
                        if (config.logAcceptedConnections()) {
                            Endpoint endpoint = connectedMiddle.endpoint();
                            log("accepted " + peer + ": dc=" + backendDc
                                    + " backend=" + endpoint.host() + ":" + endpoint.port()
                                    + " adtag=on");
                        }
                        Socket middle = connectedMiddle.socket();
                        InputStream middleIn = middle.getInputStream();
                        OutputStream middleOut = middle.getOutputStream();
                        MiddleProxyConnection middleProxy = connectedMiddle.connection();

                        Thread upstream = new Thread(
                                () -> pipe(clientStreams.input(), middleOut, handshake.clientToProxyCipher(), middleProxy.clientToBackend(), null, middle),
                                "jmtproxy-upstream-" + peer
                        );
                        upstream.start();
                        pipe(middleIn, clientStreams.output(), null, middleProxy.backendToClient(), handshake.proxyToClientCipher(), clientSocket);
                        closeQuietly(clientSocket);
                        closeQuietly(middle);
                        joinQuietly(upstream);
                    }
                } else {
                    List<Endpoint> endpoints = config.dcMaps().endpoints(backendDc, clientFamily);
                    if (endpoints.isEmpty()) {
                        throw new IOException("unsupported dc " + handshake.dcId());
                    }
                    try (ConnectedTelegram connectedTelegram = connectTelegram(endpoints, config.connectTimeoutMillis(), backendDc)) {
                        if (config.logAcceptedConnections()) {
                            Endpoint endpoint = connectedTelegram.endpoint();
                            log("accepted " + peer + ": dc=" + backendDc
                                    + " backend=" + endpoint.host() + ":" + endpoint.port());
                        }
                        Socket telegram = connectedTelegram.socket();
                        InputStream telegramIn = telegram.getInputStream();
                        OutputStream telegramOut = telegram.getOutputStream();

                        Thread upstream = new Thread(
                                () -> pipe(clientStreams.input(), telegramOut, handshake.clientToProxyCipher(), null, connectedTelegram.clientToBackendCipher(), telegram),
                                "jmtproxy-upstream-" + peer
                        );
                        upstream.start();
                        pipe(telegramIn, clientStreams.output(), connectedTelegram.backendToClientCipher(), null, handshake.proxyToClientCipher(), clientSocket);
                        closeQuietly(clientSocket);
                        closeQuietly(telegram);
                        joinQuietly(upstream);
                    }
                }
            } catch (Exception e) {
                if (!config.logRejectedConnections()) {
                    return;
                }
                log("closed " + peer + ": " + detailedMessage(e));
            }
        }

        private static String detailedMessage(Throwable e) {
            String message = e.getMessage();
            Throwable[] suppressed = e.getSuppressed();
            if (suppressed.length > 0 && suppressed[0].getCause() != null) {
                return message + ": " + suppressed[0].getMessage() + ": " + causeChain(suppressed[0].getCause());
            }
            return message;
        }

        private static String causeChain(Throwable e) {
            StringBuilder out = new StringBuilder();
            Throwable current = e;
            while (current != null) {
                if (!out.isEmpty()) {
                    out.append(": ");
                }
                out.append(current.getMessage());
                current = current.getCause();
            }
            return out.toString();
        }

        private static void pipe(InputStream in, OutputStream out, Cipher decrypt, StreamTransform transform, Cipher encrypt, Socket closeOnError) {
            byte[] buffer = new byte[BUFFER_SIZE];
            try {
                while (true) {
                    int read = in.read(buffer);
                    if (read < 0) {
                        break;
                    }
                    byte[] chunk = Arrays.copyOf(buffer, read);
                    if (decrypt != null) {
                        chunk = decrypt.update(chunk);
                    }
                    if (transform != null && chunk != null && chunk.length > 0) {
                        chunk = transform.apply(chunk);
                    }
                    if (encrypt != null) {
                        chunk = encrypt.update(chunk);
                    }
                    if (chunk != null && chunk.length > 0) {
                        out.write(chunk);
                        out.flush();
                    }
                }
            } catch (IOException ignored) {
                String message = ignored.getMessage();
                if (message != null
                        && !message.equals("Socket closed")
                        && !message.equals("Connection reset")
                        && !message.equals("Broken pipe")) {
                    log("pipe closed " + closeOnError.getRemoteSocketAddress() + ": " + message);
                }
                closeQuietly(closeOnError);
            }
        }

        private static void closeQuietly(Socket socket) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }

        private static void joinQuietly(Thread thread) {
            try {
                thread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        static ConnectedTelegram connectTelegram(List<Endpoint> endpoints, int timeoutMillis, int dc) throws IOException {
            IOException failure = null;
            for (Endpoint endpoint : endpoints) {
                Socket telegram = new Socket();
                try {
                    telegram.setTcpNoDelay(true);
                    telegram.connect(new InetSocketAddress(endpoint.host(), endpoint.port()), timeoutMillis);
                    BackendObfuscation obfuscation = BackendObfuscation.open(telegram.getOutputStream(), dc);
                    return new ConnectedTelegram(telegram, endpoint, obfuscation.clientToBackendCipher(), obfuscation.backendToClientCipher());
                } catch (IOException e) {
                    closeQuietly(telegram);
                    IOException endpointFailure = new IOException("failed to connect " + endpoint.host() + ":" + endpoint.port(), e);
                    if (failure == null) {
                        failure = new IOException("failed to connect Telegram DC");
                    }
                    failure.addSuppressed(endpointFailure);
                }
            }
            throw failure == null ? new IOException("no Telegram DC endpoint configured") : failure;
        }

        static ConnectedMiddleProxy connectMiddleProxy(
                List<Endpoint> endpoints,
                int timeoutMillis,
                int dc,
                ProxyTransport transport,
                Socket clientSocket,
                byte[] adTag,
                byte[] proxySecret,
                List<PublicHost> publicHosts
        ) throws IOException {
            IOException failure = null;
            for (Endpoint endpoint : endpoints) {
                Socket middle = new Socket();
                try {
                    middle.setTcpNoDelay(true);
                    middle.connect(new InetSocketAddress(endpoint.host(), endpoint.port()), timeoutMillis);
                    MiddleProxyConnection connection = MiddleProxyConnection.open(
                            middle,
                            transport,
                            clientSocket,
                            adTag,
                            proxySecret,
                            publicHosts
                    );
                    return new ConnectedMiddleProxy(middle, endpoint, connection);
                } catch (IOException e) {
                    closeQuietly(middle);
                    IOException endpointFailure = new IOException("failed to connect middle proxy " + endpoint.host() + ":" + endpoint.port(), e);
                    if (failure == null) {
                        failure = new IOException("failed to connect Telegram middle proxy");
                    }
                    failure.addSuppressed(endpointFailure);
                }
            }
            throw failure == null ? new IOException("no Telegram middle proxy endpoint configured for dc " + dc) : failure;
        }

        private static IpFamily clientFamily(Socket socket) {
            if (socket.getInetAddress() != null) {
                if (!(socket.getInetAddress() instanceof Inet6Address remoteAddress)) {
                    return IpFamily.IPV4;
                }
                if (isIpv4Mapped(remoteAddress)) {
                    return IpFamily.IPV4;
                }
                return IpFamily.IPV6;
            }
            if (socket.getLocalAddress() instanceof Inet6Address localAddress) {
                if (isIpv4Mapped(localAddress)) {
                    return IpFamily.IPV4;
                }
                return IpFamily.IPV6;
            }
            return IpFamily.IPV4;
        }

        private static boolean isIpv4Mapped(Inet6Address address) {
            byte[] bytes = address.getAddress();
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    return false;
                }
            }
            return bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff;
        }
    }

    record ClientStreams(InputStream input, OutputStream output, boolean fakeTls) {
    }

    static final class FakeTls {
        private FakeTls() {
        }

        static ClientStreams tryAccept(InputStream in, OutputStream out, byte[] secret, String tlsDomain, boolean required)
                throws IOException, GeneralSecurityException {
            byte[] first = Handshake.readExactly(in, HANDSHAKE_SIZE);
            if (!isTlsClientHello(first)) {
                if (required) {
                    throw new IOException("FakeTLS required but client did not send TLS ClientHello");
                }
                return new ClientStreams(new java.io.SequenceInputStream(new ByteArrayInputStream(first), in), out, false);
            }

            if (!required) {
                throw new IOException("FakeTLS client used but current mode is not tls");
            }
            if (tlsDomain == null || tlsDomain.isBlank()) {
                throw new IOException("FakeTLS client used but TLS_DOMAIN is not configured");
            }

            int recordLength = ((first[3] & 0xff) << 8) | (first[4] & 0xff);
            int totalClientHelloLength = 5 + recordLength;
            if (totalClientHelloLength < HANDSHAKE_SIZE) {
                throw new IOException("invalid FakeTLS ClientHello length");
            }
            byte[] rest = Handshake.readExactly(in, totalClientHelloLength - HANDSHAKE_SIZE);
            byte[] clientHello = concat(first, rest);
            verifyClientHello(clientHello, secret, tlsDomain);
            out.write(buildServerHello(clientHello, secret));
            out.flush();
            return new ClientStreams(new TlsRecordInputStream(in), new TlsRecordOutputStream(out), true);
        }

        private static void verifyClientHello(byte[] clientHello, byte[] secret, String tlsDomain)
                throws IOException, GeneralSecurityException {
            byte[] digest = Arrays.copyOfRange(clientHello, 11, 43);
            byte[] zeroed = clientHello.clone();
            Arrays.fill(zeroed, 11, 43, (byte) 0);

            byte[] computed = hmacSha256(secret, zeroed);
            for (int i = 0; i < 28; i++) {
                if (computed[i] != digest[i]) {
                    throw new IOException("invalid FakeTLS secret");
                }
            }

            long timestamp = (Integer.toUnsignedLong(littleEndianInt(computed, 28))
                    ^ Integer.toUnsignedLong(littleEndianInt(digest, 28)));
            long now = Instant.now().getEpochSecond();
            if (Math.abs(timestamp - now) > 600) {
                throw new IOException("stale FakeTLS handshake");
            }

            // The SNI is already covered by the HMAC over the full ClientHello.
        }

        private static String parseSni(byte[] clientHello) {
            if (clientHello.length <= 129) {
                return "";
            }
            int length = clientHello[128] & 0xff;
            if (129 + length > clientHello.length) {
                return "";
            }
            return new String(clientHello, 129, length, StandardCharsets.UTF_8);
        }

        private static byte[] buildServerHello(byte[] clientHello, byte[] secret) throws GeneralSecurityException {
            byte[] digest = Arrays.copyOfRange(clientHello, 11, 43);
            int sessionIdLength = clientHello[43] & 0xff;
            byte[] sessionId = 44 + sessionIdLength > clientHello.length
                    ? new byte[0]
                    : Arrays.copyOfRange(clientHello, 44, 44 + sessionIdLength);
            int certificateLength = 1024 + new SecureRandom().nextInt(3 * 1024);
            byte[] certificateBytes = new byte[certificateLength];
            new SecureRandom().nextBytes(certificateBytes);

            byte[] firstPart = TLS_SERVER_FIRST_PART.clone();
            byte[] secondPart = TLS_SERVER_SECOND_PART.clone();
            writeUInt16BE(firstPart, 3, 90 + sessionId.length);
            writeUInt32BE(firstPart, 5, 86 + sessionId.length);
            firstPart[5] = 2;
            firstPart[43] = (byte) sessionId.length;

            byte[] x25519 = new byte[32];
            new SecureRandom().nextBytes(x25519);
            System.arraycopy(x25519, 0, secondPart, 13, x25519.length);
            writeUInt16BE(secondPart, 60, certificateLength);

            byte[] digestPacket = concat(digest, firstPart, sessionId, secondPart, certificateBytes);
            byte[] hmac = hmacSha256(secret, digestPacket);
            byte[] mainPacket = Arrays.copyOfRange(digestPacket, 32, digestPacket.length);
            System.arraycopy(hmac, 0, mainPacket, 11, hmac.length);
            return mainPacket;
        }

        private static boolean isTlsClientHello(byte[] data) {
            return data.length >= 11
                    && data[0] == 0x16
                    && data[1] == 0x03
                    && data[5] == 0x01
                    && data[9] == 0x03
                    && data[10] == 0x03;
        }

        private static byte[] hmacSha256(byte[] key, byte[] data) throws GeneralSecurityException {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        }

        private static int littleEndianInt(byte[] bytes, int offset) {
            return (bytes[offset] & 0xff)
                    | ((bytes[offset + 1] & 0xff) << 8)
                    | ((bytes[offset + 2] & 0xff) << 16)
                    | ((bytes[offset + 3] & 0xff) << 24);
        }

        private static void writeUInt16BE(byte[] bytes, int offset, int value) {
            bytes[offset] = (byte) (value >>> 8);
            bytes[offset + 1] = (byte) value;
        }

        private static void writeUInt32BE(byte[] bytes, int offset, int value) {
            bytes[offset] = (byte) (value >>> 24);
            bytes[offset + 1] = (byte) (value >>> 16);
            bytes[offset + 2] = (byte) (value >>> 8);
            bytes[offset + 3] = (byte) value;
        }

        private static byte[] concat(byte[]... parts) {
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
    }

    static final class TlsRecordInputStream extends InputStream {
        private final InputStream in;
        private byte[] buffer = new byte[0];
        private int offset;

        TlsRecordInputStream(InputStream in) {
            this.in = in;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int read = read(one, 0, 1);
            return read < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] bytes, int off, int len) throws IOException {
            Objects.checkFromIndexSize(off, len, bytes.length);
            if (len == 0) {
                return 0;
            }
            while (offset >= buffer.length) {
                if (!readNextRecord()) {
                    return -1;
                }
            }
            int copied = Math.min(len, buffer.length - offset);
            System.arraycopy(buffer, offset, bytes, off, copied);
            offset += copied;
            return copied;
        }

        private boolean readNextRecord() throws IOException {
            byte[] header = readAtMostHeader();
            if (header == null) {
                return false;
            }
            int type = header[0] & 0xff;
            if (header[1] != 0x03 || header[2] != 0x03) {
                throw new IOException("invalid FakeTLS record version");
            }
            int length = ((header[3] & 0xff) << 8) | (header[4] & 0xff);
            byte[] payload = Handshake.readExactly(in, length);
            if (type == 0x14) {
                return readNextRecord();
            }
            if (type != 0x17) {
                throw new IOException("invalid FakeTLS record type");
            }
            buffer = payload;
            offset = 0;
            return true;
        }

        private byte[] readAtMostHeader() throws IOException {
            byte[] header = new byte[5];
            int offset = 0;
            while (offset < header.length) {
                int read = in.read(header, offset, header.length - offset);
                if (read < 0) {
                    if (offset == 0) {
                        return null;
                    }
                    throw new EOFException("connection closed during FakeTLS record header");
                }
                offset += read;
            }
            return header;
        }
    }

    static final class TlsRecordOutputStream extends OutputStream {
        private final OutputStream out;

        TlsRecordOutputStream(OutputStream out) {
            this.out = out;
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[]{(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] bytes, int off, int len) throws IOException {
            Objects.checkFromIndexSize(off, len, bytes.length);
            int remaining = len;
            int offset = off;
            while (remaining > 0) {
                int chunk = Math.min(remaining, TLS_MAX_CHUNK_SIZE);
                out.write(0x17);
                out.write(0x03);
                out.write(0x03);
                out.write((chunk >>> 8) & 0xff);
                out.write(chunk & 0xff);
                out.write(bytes, offset, chunk);
                offset += chunk;
                remaining -= chunk;
            }
        }

        @Override
        public void flush() throws IOException {
            out.flush();
        }
    }

    static final class Handshake {
        private final int dcId;
        private final Cipher clientToProxyCipher;
        private final Cipher proxyToClientCipher;
        private final ProxyTransport transport;

        private Handshake(int dcId, Cipher clientToProxyCipher, Cipher proxyToClientCipher, ProxyTransport transport) {
            this.dcId = dcId;
            this.clientToProxyCipher = clientToProxyCipher;
            this.proxyToClientCipher = proxyToClientCipher;
            this.transport = transport;
        }

        static Handshake read(InputStream in, byte[] secret, Modes modes, boolean fakeTls) throws IOException, GeneralSecurityException {
            byte[] init = readExactly(in, HANDSHAKE_SIZE);
            Cipher clientToProxy = cipher(Cipher.DECRYPT_MODE, init, secret);
            byte[] decodedInit = clientToProxy.update(init);
            if (decodedInit == null || decodedInit.length != HANDSHAKE_SIZE) {
                throw new IOException("invalid obfuscated init");
            }
            ProxyTransport transport = modes.transport(decodedInit, fakeTls);
            if (transport == null) {
                throw new IOException("unsupported transport or invalid secret");
            }
            int dcId = littleEndianSignedShort(decodedInit, 60);

            byte[] plainInit = init.clone();
            System.arraycopy(decodedInit, 56, plainInit, 56, 8);
            byte[] reversed = reverse(plainInit);
            Cipher proxyToClient = cipher(Cipher.ENCRYPT_MODE, reversed, secret);
            return new Handshake(dcId, clientToProxy, proxyToClient, transport);
        }

        int dcId() {
            return dcId;
        }

        int backendDc() {
            int dc = Math.abs(dcId);
            if (dc >= 10000) {
                dc -= 10000;
            }
            return dc;
        }

        Cipher clientToProxyCipher() {
            return clientToProxyCipher;
        }

        Cipher proxyToClientCipher() {
            return proxyToClientCipher;
        }

        ProxyTransport transport() {
            return transport;
        }

        private static Cipher cipher(int mode, byte[] init, byte[] secret) throws GeneralSecurityException {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(init, 8, 32);
            sha256.update(secret);
            byte[] key = sha256.digest();
            byte[] iv = Arrays.copyOfRange(init, 40, 56);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher;
        }

        private static byte[] reverse(byte[] input) {
            byte[] out = input.clone();
            for (int i = 0, j = out.length - 1; i < j; i++, j--) {
                byte tmp = out[i];
                out[i] = out[j];
                out[j] = tmp;
            }
            return out;
        }

        private static int littleEndianSignedShort(byte[] bytes, int offset) {
            int value = (bytes[offset] & 0xff) | (bytes[offset + 1] << 8);
            return (short) value;
        }

        private static byte[] readExactly(InputStream in, int length) throws IOException {
            byte[] out = new byte[length];
            int offset = 0;
            while (offset < length) {
                int read = in.read(out, offset, length - offset);
                if (read < 0) {
                    throw new EOFException("connection closed during handshake");
                }
                offset += read;
            }
            return out;
        }
    }

    record ConnectedTelegram(
            Socket socket,
            Endpoint endpoint,
            Cipher clientToBackendCipher,
            Cipher backendToClientCipher
    ) implements AutoCloseable {
        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    record ConnectedMiddleProxy(
            Socket socket,
            Endpoint endpoint,
            MiddleProxyConnection connection
    ) implements AutoCloseable {
        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    interface StreamTransform {
        byte[] apply(byte[] input) throws IOException;
    }

    record Endpoint(String host, int port) {
    }

    record BackendObfuscation(Cipher clientToBackendCipher, Cipher backendToClientCipher) {
        static BackendObfuscation open(OutputStream out, int dc) throws IOException {
            byte[] init = generateInit(dc);
            Cipher clientToBackend;
            Cipher backendToClient;
            try {
                clientToBackend = cipher(Cipher.ENCRYPT_MODE, init);
                byte[] encryptedInit = clientToBackend.update(init);
                System.arraycopy(init, 8, encryptedInit, 8, 48);
                backendToClient = cipher(Cipher.DECRYPT_MODE, reverse(init));
                out.write(encryptedInit);
            } catch (GeneralSecurityException e) {
                throw new IOException("failed to initialize Telegram backend obfuscation", e);
            }
            out.flush();
            return new BackendObfuscation(clientToBackend, backendToClient);
        }

        private static byte[] generateInit(int dc) throws IOException {
            byte[] init = new byte[HANDSHAKE_SIZE];
            SecureRandom random = new SecureRandom();
            for (int attempt = 0; attempt < 100; attempt++) {
                random.nextBytes(init);
                if (isForbiddenInit(init)) {
                    continue;
                }
                System.arraycopy(BACKEND_TRANSPORT_HEADER, 0, init, 56, BACKEND_TRANSPORT_HEADER.length);
                writeLittleEndianShort(init, 60, dc == 0 ? 2 : dc);
                init[62] = 0;
                init[63] = 0;
                return init;
            }
            throw new IOException("failed to generate Telegram backend obfuscation init");
        }

        private static Cipher cipher(int mode, byte[] init) throws GeneralSecurityException {
            byte[] key = Arrays.copyOfRange(init, 8, 40);
            byte[] iv = Arrays.copyOfRange(init, 40, 56);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher;
        }

        private static boolean isForbiddenInit(byte[] init) {
            int first = (init[0] & 0xff)
                    | ((init[1] & 0xff) << 8)
                    | ((init[2] & 0xff) << 16)
                    | ((init[3] & 0xff) << 24);
            return init[0] == (byte) 0xef
                    || first == 0x44414548
                    || first == 0x54534f50
                    || first == 0x20544547
                    || first == 0x4954504f
                    || first == 0x02010316
                    || first == 0xdddddddd
                    || first == 0xeeeeeeee
                    || (init[4] | init[5] | init[6] | init[7]) == 0;
        }

        private static void writeLittleEndianShort(byte[] bytes, int offset, int value) {
            bytes[offset] = (byte) value;
            bytes[offset + 1] = (byte) (value >>> 8);
        }

        private static byte[] reverse(byte[] input) {
            byte[] out = input.clone();
            for (int i = 8, j = 55; i < j; i++, j--) {
                byte tmp = out[i];
                out[i] = out[j];
                out[j] = tmp;
            }
            return out;
        }
    }

    static final class MiddleProxyState {
        private final DcMaps maps;
        private final byte[] secret;

        private MiddleProxyState(DcMaps maps, byte[] secret) {
            this.maps = maps;
            this.secret = secret.clone();
        }

        static MiddleProxyState load(int timeoutMillis) {
            try {
                byte[] secret = fetchProxySecret(timeoutMillis);
                Map<Integer, List<Endpoint>> v4 = fetchMiddleProxyMap(
                        TELEGRAM_PROXY_CONFIG_IPV4,
                        IpFamily.IPV4,
                        timeoutMillis
                );
                Map<Integer, List<Endpoint>> v6 = fetchMiddleProxyMap(
                        TELEGRAM_PROXY_CONFIG_IPV6,
                        IpFamily.IPV6,
                        timeoutMillis
                );
                if (v4.isEmpty()) {
                    v4 = parseMiddleProxyConfig(BUILTIN_MIDDLE_PROXY_CONFIG_IPV4, IpFamily.IPV4);
                }
                if (v6.isEmpty()) {
                    v6 = parseMiddleProxyConfig(BUILTIN_MIDDLE_PROXY_CONFIG_IPV6, IpFamily.IPV6);
                }
                if (v4.isEmpty() && v6.isEmpty()) {
                    throw new IOException("Telegram middle proxy config did not contain any usable endpoint");
                }
                return new MiddleProxyState(new DcMaps(v4, v6), secret);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to initialize AD_TAG middle proxy", e);
            }
        }

        List<Endpoint> endpoints(int dc, IpFamily preferredFamily) {
            return maps.endpoints(dc, preferredFamily);
        }

        byte[] secret() {
            return secret.clone();
        }

        private static byte[] fetchProxySecret(int timeoutMillis) throws IOException {
            byte[] builtIn = Hex.decode(BUILTIN_MIDDLE_PROXY_SECRET_HEX);
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(timeoutMillis))
                    .build();
            HttpRequest request = HttpRequest.newBuilder(URI.create(TELEGRAM_PROXY_SECRET))
                    .timeout(Duration.ofMillis(timeoutMillis))
                    .header("User-Agent", "jmtproxy/0.1")
                    .GET()
                    .build();
            try {
                HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    byte[] secret = response.body();
                    validateProxySecret(secret);
                    return secret;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                validateProxySecret(builtIn);
                return builtIn;
            } catch (IOException e) {
                // Fall back to the built-in snapshot below.
            }

            validateProxySecret(builtIn);
            return builtIn;
        }

        private static void validateProxySecret(byte[] secret) throws IOException {
            if (secret == null || secret.length < 32) {
                throw new IOException("Telegram proxy-secret is too short");
            }
        }

        private static Map<Integer, List<Endpoint>> fetchMiddleProxyMap(
                String url,
                IpFamily family,
                int timeoutMillis
        ) throws IOException {
            String body = null;
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(timeoutMillis))
                    .build();
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofMillis(timeoutMillis))
                    .header("User-Agent", "jmtproxy/0.1")
                    .GET()
                    .build();
            try {
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    body = response.body();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted while fetching Telegram middle proxy config", e);
            } catch (IOException e) {
                // Fall back to the built-in snapshot in load().
            }
            if (body == null || body.isBlank()) {
                return Collections.emptyMap();
            }
            return parseMiddleProxyConfig(body, family);
        }

        static Map<Integer, List<Endpoint>> parseMiddleProxyConfig(String body, IpFamily family) {
            Map<Integer, List<Endpoint>> out = new HashMap<>();
            for (String line : body.split("\\R")) {
                Matcher matcher = PROXY_FOR_PATTERN.matcher(line);
                if (!matcher.matches()) {
                    continue;
                }
                int dc = Math.abs(Integer.parseInt(matcher.group(1)));
                Endpoint endpoint;
                try {
                    endpoint = Dc203Updater.parseEndpoint(matcher.group(2));
                } catch (IllegalArgumentException e) {
                    continue;
                }
                if (Config.inferIpFamily(endpoint.host()) != family) {
                    continue;
                }
                List<Endpoint> endpoints = out.computeIfAbsent(dc, ignored -> new ArrayList<>());
                if (!endpoints.contains(endpoint)) {
                    endpoints.add(endpoint);
                }
            }
            Map<Integer, List<Endpoint>> immutable = new HashMap<>();
            for (Map.Entry<Integer, List<Endpoint>> entry : out.entrySet()) {
                immutable.put(entry.getKey(), List.copyOf(entry.getValue()));
            }
            return Map.copyOf(immutable);
        }
    }

    static final class MiddleProxyConnection {
        private final StreamTransform clientToBackend;
        private final StreamTransform backendToClient;

        private MiddleProxyConnection(StreamTransform clientToBackend, StreamTransform backendToClient) {
            this.clientToBackend = clientToBackend;
            this.backendToClient = backendToClient;
        }

        static MiddleProxyConnection open(
                Socket middle,
                ProxyTransport transport,
                Socket clientSocket,
                byte[] adTag,
                byte[] proxySecret,
                List<PublicHost> publicHosts
        ) throws IOException {
            InputStream in = middle.getInputStream();
            OutputStream out = middle.getOutputStream();
            byte[] clientNonce = randomBytes(16);
            int cryptoTs = (int) (Instant.now().getEpochSecond() & 0xffff_ffffL);

            MiddleFrameCodec plainFrames = new MiddleFrameCodec(null, null, -2, -2);
            plainFrames.writeFrame(out, buildNoncePayload(proxySecret, cryptoTs, clientNonce));
            byte[] nonceAnswer = plainFrames.readFrame(in);
            if (nonceAnswer.length < 32 || littleEndianInt(nonceAnswer, 0) != RPC_NONCE) {
                throw new IOException("bad Telegram middle proxy nonce answer");
            }
            if (!Arrays.equals(Arrays.copyOfRange(nonceAnswer, 4, 8), Arrays.copyOf(proxySecret, 4))) {
                throw new IOException("Telegram middle proxy key selector mismatch");
            }
            if (littleEndianInt(nonceAnswer, 8) != RPC_CRYPTO_AES) {
                throw new IOException("Telegram middle proxy does not support AES crypto");
            }
            int serverTs = littleEndianInt(nonceAnswer, 12);
            long serverTsUnsigned = Integer.toUnsignedLong(serverTs);
            long cryptoTsUnsigned = Integer.toUnsignedLong(cryptoTs);
            long tsDiff = Math.abs(serverTsUnsigned - cryptoTsUnsigned);
            tsDiff = Math.min(tsDiff, (1L << 32) - tsDiff);
            if (tsDiff > 30) {
                throw new IOException("Telegram middle proxy timestamp skew is too large");
            }
            byte[] serverNonce = Arrays.copyOfRange(nonceAnswer, 16, 32);

            MiddleAddressMaterial kdf = MiddleAddressMaterial.fromMiddleSocket(middle, publicHosts);
            Cipher writeCipher = middleCipher(
                    Cipher.ENCRYPT_MODE,
                    serverNonce,
                    clientNonce,
                    littleEndianIntBytes(cryptoTs),
                    kdf.serverIp(),
                    kdf.clientPort(),
                    "CLIENT",
                    kdf.clientIp(),
                    kdf.serverPort(),
                    proxySecret,
                    kdf.clientIpv6(),
                    kdf.serverIpv6()
            );
            Cipher readCipher = middleCipher(
                    Cipher.DECRYPT_MODE,
                    serverNonce,
                    clientNonce,
                    littleEndianIntBytes(cryptoTs),
                    kdf.serverIp(),
                    kdf.clientPort(),
                    "SERVER",
                    kdf.clientIp(),
                    kdf.serverPort(),
                    proxySecret,
                    kdf.clientIpv6(),
                    kdf.serverIpv6()
            );
            MiddleFrameCodec encryptedFrames = new MiddleFrameCodec(writeCipher, readCipher, -1, -1);
            encryptedFrames.writeFrame(out, buildHandshakePayload(kdf.clientIp(), middle.getLocalPort(), kdf.serverIp(), middle.getPort()));
            byte[] handshakeAnswer = encryptedFrames.readFrame(in);
            if (handshakeAnswer.length != 32) {
                throw new IOException("bad Telegram middle proxy handshake answer");
            }
            int answerType = littleEndianInt(handshakeAnswer, 0);
            if (answerType == RPC_HANDSHAKE_ERROR) {
                throw new IOException("Telegram middle proxy rejected handshake");
            }
            if (answerType != RPC_HANDSHAKE) {
                throw new IOException("bad Telegram middle proxy handshake answer");
            }

            byte[] clientAddr = ipPortBytes(clientSocket.getInetAddress(), clientSocket.getPort());
            InetAddress publicOrLocal = publicAddressFor(ProxyConnection.clientFamily(clientSocket), publicHosts);
            if (publicOrLocal == null) {
                publicOrLocal = clientSocket.getLocalAddress();
            }
            byte[] ourAddr = ipPortBytes(publicOrLocal, clientSocket.getLocalPort());
            long connId = new SecureRandom().nextLong() | 1L;
            StreamTransform c2m = new MiddleRequestTransform(encryptedFrames, out, transport, clientAddr, ourAddr, connId, adTag);
            StreamTransform m2c = new MiddleAnswerTransform(encryptedFrames, transport, out);
            return new MiddleProxyConnection(c2m, m2c);
        }

        StreamTransform clientToBackend() {
            return clientToBackend;
        }

        StreamTransform backendToClient() {
            return backendToClient;
        }

        private static byte[] buildNoncePayload(byte[] proxySecret, int cryptoTs, byte[] clientNonce) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream(32);
            writeLittleEndianInt(out, RPC_NONCE);
            out.write(Arrays.copyOf(proxySecret, 4));
            writeLittleEndianInt(out, RPC_CRYPTO_AES);
            writeLittleEndianInt(out, cryptoTs);
            out.write(clientNonce);
            return out.toByteArray();
        }

        private static byte[] buildHandshakePayload(byte[] ourIp, int ourPort, byte[] peerIp, int peerPort) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream(32);
            writeLittleEndianInt(out, RPC_HANDSHAKE);
            writeLittleEndianInt(out, 0);
            out.write(Arrays.copyOf(ourIp, 4));
            writeLittleEndianShort(out, ourPort);
            writeLittleEndianShort(out, (int) ProcessHandle.current().pid());
            writeLittleEndianInt(out, (int) (Instant.now().getEpochSecond() & 0xffff_ffffL));
            out.write(Arrays.copyOf(peerIp, 4));
            writeLittleEndianShort(out, peerPort);
            writeLittleEndianShort(out, 0);
            writeLittleEndianInt(out, 0);
            return out.toByteArray();
        }

        private static Cipher middleCipher(
                int mode,
                byte[] serverNonce,
                byte[] clientNonce,
                byte[] cryptoTs,
                byte[] serverIp,
                byte[] clientPort,
                String purpose,
                byte[] clientIp,
                byte[] serverPort,
                byte[] proxySecret,
                byte[] clientIpv6,
                byte[] serverIpv6
        ) throws IOException {
            try {
                ByteArrayOutputStream prekey = new ByteArrayOutputStream();
                prekey.write(serverNonce);
                prekey.write(clientNonce);
                prekey.write(cryptoTs);
                prekey.write(serverIp == null ? new byte[4] : serverIp);
                prekey.write(clientPort);
                prekey.write(purpose.getBytes(StandardCharsets.US_ASCII));
                prekey.write(clientIp == null ? new byte[4] : clientIp);
                prekey.write(serverPort);
                prekey.write(proxySecret);
                prekey.write(serverNonce);
                if (clientIpv6 != null && serverIpv6 != null) {
                    prekey.write(clientIpv6);
                    prekey.write(serverIpv6);
                }
                prekey.write(clientNonce);
                byte[] material = prekey.toByteArray();

                MessageDigest md5 = MessageDigest.getInstance("MD5");
                md5.update(material, 1, material.length - 1);
                byte[] md5First = md5.digest();
                byte[] sha1 = MessageDigest.getInstance("SHA-1").digest(material);
                byte[] key = new byte[32];
                System.arraycopy(md5First, 0, key, 0, 12);
                System.arraycopy(sha1, 0, key, 12, 20);
                md5.reset();
                md5.update(material, 2, material.length - 2);
                byte[] iv = md5.digest();

                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
                return cipher;
            } catch (GeneralSecurityException e) {
                throw new IOException("failed to initialize Telegram middle proxy crypto", e);
            }
        }

        private static byte[] ipPortBytes(InetAddress address, int port) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream(20);
            byte[] ip = address.getAddress();
            if (ip.length == 4) {
                out.write(new byte[10]);
                out.write(0xff);
                out.write(0xff);
                out.write(ip);
            } else {
                out.write(ip);
            }
            writeLittleEndianInt(out, port);
            return out.toByteArray();
        }

        private static InetAddress publicAddressFor(IpFamily family, List<PublicHost> publicHosts) {
            for (PublicHost publicHost : publicHosts) {
                if (publicHost.family() != family) {
                    continue;
                }
                try {
                    return InetAddress.getByName(publicHost.host());
                } catch (IOException e) {
                    return null;
                }
            }
            return null;
        }
    }

    record MiddleAddressMaterial(
            byte[] serverIp,
            byte[] serverPort,
            byte[] clientIp,
            byte[] clientPort,
            byte[] serverIpv6,
            byte[] clientIpv6
    ) {
        static MiddleAddressMaterial fromMiddleSocket(Socket socket, List<PublicHost> publicHosts) throws IOException {
            InetAddress serverAddress = socket.getInetAddress();
            IpFamily family = serverAddress.getAddress().length == 16 ? IpFamily.IPV6 : IpFamily.IPV4;
            InetAddress clientAddress = MiddleProxyConnection.publicAddressFor(family, publicHosts);
            if (clientAddress == null) {
                clientAddress = socket.getLocalAddress();
            }
            byte[] serverBytes = serverAddress.getAddress();
            byte[] clientBytes = clientAddress.getAddress();
            byte[] serverPort = littleEndianShortBytes(socket.getPort());
            byte[] clientPort = littleEndianShortBytes(socket.getLocalPort());
            if (serverBytes.length == 4 && clientBytes.length == 4) {
                return new MiddleAddressMaterial(reverseCopy(serverBytes), serverPort, reverseCopy(clientBytes), clientPort, null, null);
            }
            if (serverBytes.length == 16 && clientBytes.length == 16) {
                return new MiddleAddressMaterial(new byte[4], serverPort, new byte[4], clientPort, serverBytes, clientBytes);
            }
            throw new IOException("middle proxy address family mismatch");
        }
    }

    static final class MiddleFrameCodec {
        private final Cipher encrypt;
        private final Cipher decrypt;
        private int writeSeq;
        private int readSeq;
        private byte[] decryptedBuffer = new byte[0];
        private byte[] encryptedRemainder = new byte[0];

        MiddleFrameCodec(Cipher encrypt, Cipher decrypt, int writeSeq, int readSeq) {
            this.encrypt = encrypt;
            this.decrypt = decrypt;
            this.writeSeq = writeSeq;
            this.readSeq = readSeq;
        }

        synchronized void writeFrame(OutputStream out, byte[] payload) throws IOException {
            byte[] frame = buildRpcFrame(writeSeq++, payload);
            if (encrypt != null) {
                frame = encryptPadded(frame);
            }
            out.write(frame);
            out.flush();
        }

        synchronized byte[] readFrame(InputStream in) throws IOException {
            if (decrypt == null) {
                return readPlainFrame(in);
            }
            while (true) {
                byte[] frame = pollFrame();
                if (frame != null) {
                    return frame;
                }
                feed(Handshake.readExactly(in, 16));
            }
        }

        synchronized void feed(byte[] input) throws IOException {
            if (decrypt == null) {
                appendDecrypted(input);
                return;
            }
            byte[] combined = concat(encryptedRemainder, input);
            int decryptLength = combined.length - (combined.length % 16);
            encryptedRemainder = Arrays.copyOfRange(combined, decryptLength, combined.length);
            if (decryptLength > 0) {
                byte[] decoded = decrypt.update(combined, 0, decryptLength);
                if (decoded != null && decoded.length > 0) {
                    appendDecrypted(decoded);
                }
            }
        }

        synchronized byte[] pollFrame() throws IOException {
            while (decryptedBuffer.length >= 4 && littleEndianInt(decryptedBuffer, 0) == 4) {
                consumeDecrypted(4);
            }
            if (decryptedBuffer.length < 4) {
                return null;
            }
            int totalLength = littleEndianInt(decryptedBuffer, 0);
            if (totalLength < 12 || totalLength > (1 << 24)) {
                throw new IOException("bad Telegram middle proxy frame length: " + totalLength);
            }
            if (decryptedBuffer.length < totalLength) {
                return null;
            }
            byte[] frame = Arrays.copyOfRange(decryptedBuffer, 0, totalLength);
            consumeDecrypted(totalLength);
            return verifyAndExtract(frame);
        }

        private byte[] readPlainFrame(InputStream in) throws IOException {
            byte[] len = Handshake.readExactly(in, 4);
            int totalLength = littleEndianInt(len, 0);
            if (totalLength < 12 || totalLength > (1 << 24)) {
                throw new IOException("bad Telegram middle proxy frame length: " + totalLength);
            }
            byte[] rest = Handshake.readExactly(in, totalLength - 4);
            byte[] frame = concat(len, rest);
            return verifyAndExtract(frame);
        }

        private byte[] verifyAndExtract(byte[] frame) throws IOException {
            int seq = littleEndianInt(frame, 4);
            if (seq != readSeq++) {
                throw new IOException("bad Telegram middle proxy frame sequence");
            }
            int expected = littleEndianInt(frame, frame.length - 4);
            CRC32 crc32 = new CRC32();
            crc32.update(frame, 0, frame.length - 4);
            if ((int) crc32.getValue() != expected) {
                throw new IOException("bad Telegram middle proxy frame checksum");
            }
            return Arrays.copyOfRange(frame, 8, frame.length - 4);
        }

        private byte[] buildRpcFrame(int seq, byte[] payload) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream(12 + payload.length);
            writeLittleEndianInt(out, 12 + payload.length);
            writeLittleEndianInt(out, seq);
            out.write(payload);
            CRC32 crc32 = new CRC32();
            byte[] withoutCrc = out.toByteArray();
            crc32.update(withoutCrc, 0, withoutCrc.length);
            writeLittleEndianInt(out, (int) crc32.getValue());
            return out.toByteArray();
        }

        private byte[] encryptPadded(byte[] frame) {
            int padding = encryptedPaddingLength(frame.length);
            byte[] padded = Arrays.copyOf(frame, frame.length + padding);
            for (int i = 0; i < padding; i++) {
                padded[frame.length + i] = MIDDLE_PADDING_FILLER[i % MIDDLE_PADDING_FILLER.length];
            }
            return encrypt.update(padded);
        }

        private static int encryptedPaddingLength(int totalLength) {
            return (16 - (totalLength % 16)) % 16;
        }

        private void appendDecrypted(byte[] input) {
            byte[] out = Arrays.copyOf(decryptedBuffer, decryptedBuffer.length + input.length);
            System.arraycopy(input, 0, out, decryptedBuffer.length, input.length);
            decryptedBuffer = out;
        }

        private void consumeDecrypted(int count) {
            decryptedBuffer = Arrays.copyOfRange(decryptedBuffer, count, decryptedBuffer.length);
        }
    }

    static final class MiddleRequestTransform implements StreamTransform {
        private final MiddleFrameCodec frames;
        private final OutputStream middleOut;
        private final ProxyTransport transport;
        private final ClientFrameReader clientFrames;
        private final byte[] clientAddr;
        private final byte[] ourAddr;
        private final long connId;
        private final byte[] adTag;

        MiddleRequestTransform(MiddleFrameCodec frames, OutputStream middleOut, ProxyTransport transport, byte[] clientAddr, byte[] ourAddr, long connId, byte[] adTag) {
            this.frames = frames;
            this.middleOut = middleOut;
            this.transport = transport;
            this.clientFrames = new ClientFrameReader(transport);
            this.clientAddr = clientAddr.clone();
            this.ourAddr = ourAddr.clone();
            this.connId = connId;
            this.adTag = adTag.clone();
        }

        @Override
        public byte[] apply(byte[] input) throws IOException {
            List<ClientFrame> incomingFrames = clientFrames.feed(input);
            for (ClientFrame frame : incomingFrames) {
                int flags = RPC_FLAG_MAGIC | RPC_FLAG_EXTMODE2 | RPC_FLAG_HAS_AD_TAG | transport.middleProxyFlag();
                if (frame.quickAck()) {
                    flags |= RPC_FLAG_QUICKACK;
                }
                if (startsWithZeros(frame.payload(), 8)) {
                    flags |= RPC_FLAG_NOT_ENCRYPTED;
                }

                ByteArrayOutputStream payload = new ByteArrayOutputStream(128 + frame.payload().length);
                writeLittleEndianInt(payload, RPC_PROXY_REQ);
                writeLittleEndianInt(payload, flags);
                writeLittleEndianLong(payload, connId);
                payload.write(clientAddr);
                payload.write(ourAddr);
                writeProxyTagExtra(payload, adTag);
                payload.write(frame.payload());

                frames.writeFrame(middleOut, payload.toByteArray());
            }
            return new byte[0];
        }

        private static void writeProxyTagExtra(OutputStream out, byte[] adTag) throws IOException {
            ByteArrayOutputStream extra = new ByteArrayOutputStream();
            writeLittleEndianInt(extra, TL_PROXY_TAG);
            writeTlBytes(extra, adTag);
            byte[] extraBytes = extra.toByteArray();
            writeLittleEndianInt(out, extraBytes.length);
            out.write(extraBytes);
        }

        private static void writeTlBytes(OutputStream out, byte[] bytes) throws IOException {
            if (bytes.length >= 254) {
                out.write(0xfe);
                out.write(bytes.length & 0xff);
                out.write((bytes.length >>> 8) & 0xff);
                out.write((bytes.length >>> 16) & 0xff);
                out.write(bytes);
                int padding = (4 - (bytes.length % 4)) % 4;
                out.write(new byte[padding]);
                return;
            }
            out.write(bytes.length);
            out.write(bytes);
            int padding = (4 - ((1 + bytes.length) % 4)) % 4;
            out.write(new byte[padding]);
        }

        private static boolean startsWithZeros(byte[] bytes, int count) {
            if (bytes.length < count) {
                return false;
            }
            for (int i = 0; i < count; i++) {
                if (bytes[i] != 0) {
                    return false;
                }
            }
            return true;
        }
    }

    static final class MiddleAnswerTransform implements StreamTransform {
        private final MiddleFrameCodec frames;
        private final ClientFrameWriter clientFrames;
        private final OutputStream middleOut;

        MiddleAnswerTransform(MiddleFrameCodec frames, ProxyTransport transport, OutputStream middleOut) {
            this.frames = frames;
            this.clientFrames = new ClientFrameWriter(transport);
            this.middleOut = middleOut;
        }

        @Override
        public byte[] apply(byte[] input) throws IOException {
            frames.feed(input);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] frame;
            while ((frame = frames.pollFrame()) != null) {
                if (frame.length < 4) {
                    continue;
                }
                int type = littleEndianInt(frame, 0);
                if (type == RPC_PROXY_ANS && frame.length >= 16) {
                    int flags = littleEndianInt(frame, 4);
                    byte[] data = Arrays.copyOfRange(frame, 16, frame.length);
                    out.write(clientFrames.writeData(data, (flags & RPC_FLAG_QUICKACK) != 0));
                } else if (type == RPC_SIMPLE_ACK && frame.length >= 16) {
                    int confirm = littleEndianInt(frame, 12);
                    out.write(clientFrames.writeAck(confirm));
                } else if (type == RPC_CLOSE_EXT || type == RPC_CLOSE_CONN) {
                    throw new EOFException("Telegram middle proxy closed connection");
                } else if (type == RPC_PING && frame.length >= 12) {
                    ByteArrayOutputStream pong = new ByteArrayOutputStream(12);
                    writeLittleEndianInt(pong, RPC_PONG);
                    pong.write(frame, 4, 8);
                    frames.writeFrame(middleOut, pong.toByteArray());
                } else if (type == RPC_PONG) {
                    // Keepalive answer; no client payload.
                } else {
                    throw new IOException("unknown Telegram middle proxy answer");
                }
            }
            return out.toByteArray();
        }
    }

    record ClientFrame(byte[] payload, boolean quickAck) {
    }

    static final class ClientFrameReader {
        private final ProxyTransport transport;
        private byte[] buffer = new byte[0];

        ClientFrameReader(ProxyTransport transport) {
            this.transport = transport;
        }

        List<ClientFrame> feed(byte[] input) throws IOException {
            append(input);
            List<ClientFrame> out = new ArrayList<>();
            while (true) {
                ClientFrame frame = poll();
                if (frame == null) {
                    return out;
                }
                out.add(frame);
            }
        }

        private ClientFrame poll() throws IOException {
            return switch (transport) {
                case ABRIDGED -> pollAbridged();
                case INTERMEDIATE -> pollIntermediate(false);
                case PADDED_INTERMEDIATE -> pollIntermediate(true);
            };
        }

        private ClientFrame pollAbridged() throws IOException {
            if (buffer.length < 1) {
                return null;
            }
            int first = buffer[0] & 0xff;
            boolean quickAck = (first & 0x80) != 0;
            first &= 0x7f;
            int headerLength = 1;
            int lenWords;
            if (first == 0x7f) {
                if (buffer.length < 4) {
                    return null;
                }
                lenWords = (buffer[1] & 0xff) | ((buffer[2] & 0xff) << 8) | ((buffer[3] & 0xff) << 16);
                headerLength = 4;
            } else {
                lenWords = first;
            }
            int payloadLength = lenWords * 4;
            if (payloadLength > (1 << 24)) {
                throw new IOException("MTProto abridged frame too large: " + payloadLength);
            }
            if (buffer.length < headerLength + payloadLength) {
                return null;
            }
            byte[] payload = Arrays.copyOfRange(buffer, headerLength, headerLength + payloadLength);
            consume(headerLength + payloadLength);
            return new ClientFrame(payload, quickAck);
        }

        private ClientFrame pollIntermediate(boolean padded) throws IOException {
            if (buffer.length < 4) {
                return null;
            }
            int lenValue = littleEndianInt(buffer, 0);
            boolean quickAck = (lenValue & RPC_FLAG_QUICKACK) != 0;
            int wireLength = lenValue & 0x7fff_ffff;
            if (wireLength > (1 << 24)) {
                throw new IOException("MTProto frame too large: " + wireLength);
            }
            if (buffer.length < 4 + wireLength) {
                return null;
            }
            int payloadLength = wireLength;
            if (padded) {
                if (wireLength < 4) {
                    throw new IOException("invalid padded intermediate frame length: " + wireLength);
                }
                payloadLength = wireLength - (wireLength % 4);
            }
            byte[] payload = Arrays.copyOfRange(buffer, 4, 4 + payloadLength);
            consume(4 + wireLength);
            return new ClientFrame(payload, quickAck);
        }

        private void append(byte[] input) {
            byte[] out = Arrays.copyOf(buffer, buffer.length + input.length);
            System.arraycopy(input, 0, out, buffer.length, input.length);
            buffer = out;
        }

        private void consume(int count) {
            buffer = Arrays.copyOfRange(buffer, count, buffer.length);
        }
    }

    static final class ClientFrameWriter {
        private final ProxyTransport transport;
        private final SecureRandom random = new SecureRandom();

        ClientFrameWriter(ProxyTransport transport) {
            this.transport = transport;
        }

        byte[] writeData(byte[] data, boolean quickAck) throws IOException {
            return switch (transport) {
                case ABRIDGED -> writeAbridged(data, quickAck);
                case INTERMEDIATE -> writeIntermediate(data, quickAck);
                case PADDED_INTERMEDIATE -> writePadded(data, quickAck);
            };
        }

        byte[] writeAck(int confirm) {
            if (transport == ProxyTransport.ABRIDGED) {
                return new byte[]{
                        (byte) (confirm >>> 24),
                        (byte) (confirm >>> 16),
                        (byte) (confirm >>> 8),
                        (byte) confirm
                };
            }
            return littleEndianIntBytes(confirm);
        }

        private byte[] writeAbridged(byte[] data, boolean quickAck) throws IOException {
            if ((data.length % 4) != 0) {
                throw new IOException("MTProto abridged payload is not aligned");
            }
            int lenWords = data.length / 4;
            ByteArrayOutputStream out = new ByteArrayOutputStream(4 + data.length);
            if (lenWords < 0x7f) {
                int first = lenWords;
                if (quickAck) {
                    first |= 0x80;
                }
                out.write(first);
            } else if (lenWords < (1 << 24)) {
                int first = 0x7f;
                if (quickAck) {
                    first |= 0x80;
                }
                out.write(first);
                out.write(lenWords & 0xff);
                out.write((lenWords >>> 8) & 0xff);
                out.write((lenWords >>> 16) & 0xff);
            } else {
                throw new IOException("MTProto abridged payload is too large");
            }
            out.write(data);
            return out.toByteArray();
        }

        private byte[] writeIntermediate(byte[] data, boolean quickAck) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream(4 + data.length);
            int len = data.length;
            if (quickAck) {
                len |= RPC_FLAG_QUICKACK;
            }
            writeLittleEndianInt(out, len);
            out.write(data);
            return out.toByteArray();
        }

        private byte[] writePadded(byte[] data, boolean quickAck) throws IOException {
            if ((data.length % 4) != 0) {
                throw new IOException("MTProto padded intermediate payload is not aligned");
            }
            int padding = random.nextInt(3) + 1;
            byte[] paddingBytes = new byte[padding];
            random.nextBytes(paddingBytes);
            ByteArrayOutputStream out = new ByteArrayOutputStream(4 + data.length + padding);
            int len = data.length + padding;
            if (quickAck) {
                len |= RPC_FLAG_QUICKACK;
            }
            writeLittleEndianInt(out, len);
            out.write(data);
            out.write(paddingBytes);
            return out.toByteArray();
        }
    }

    record DcMaps(Map<Integer, List<Endpoint>> v4, Map<Integer, List<Endpoint>> v6) {
        List<Endpoint> endpoints(int dc, IpFamily preferredFamily) {
            List<Endpoint> endpoints = new ArrayList<>();
            Map<Integer, List<Endpoint>> primary = preferredFamily == IpFamily.IPV6 ? v6 : v4;
            Map<Integer, List<Endpoint>> fallback = preferredFamily == IpFamily.IPV6 ? v4 : v6;
            endpoints.addAll(primary.getOrDefault(dc, List.of()));
            for (Endpoint endpoint : fallback.getOrDefault(dc, List.of())) {
                if (!endpoints.contains(endpoint)) {
                    endpoints.add(endpoint);
                }
            }
            return endpoints;
        }

        void replaceDynamic(int dc, IpFamily family, List<Endpoint> endpoints) {
            Map<Integer, List<Endpoint>> map = family == IpFamily.IPV6 ? v6 : v4;
            if (map instanceof DynamicDcMap dynamicMap) {
                dynamicMap.replaceDynamic(dc, endpoints);
            }
        }
    }

    static final class DynamicDcMap extends java.util.AbstractMap<Integer, List<Endpoint>> {
        private final Map<Integer, List<Endpoint>> builtIn;
        private volatile Map<Integer, List<Endpoint>> dynamic = Collections.emptyMap();

        DynamicDcMap(Map<Integer, List<Endpoint>> builtIn) {
            this.builtIn = Map.copyOf(builtIn);
        }

        void replaceDynamic(int dc, List<Endpoint> endpoints) {
            Map<Integer, List<Endpoint>> copy = new HashMap<>(dynamic);
            copy.put(dc, List.copyOf(endpoints));
            dynamic = Map.copyOf(copy);
        }

        @Override
        public List<Endpoint> get(Object key) {
            List<Endpoint> dynamicEndpoints = dynamic.get(key);
            if (dynamicEndpoints != null) {
                return dynamicEndpoints;
            }
            return builtIn.get(key);
        }

        @Override
        public Set<Entry<Integer, List<Endpoint>>> entrySet() {
            Map<Integer, List<Endpoint>> merged = new HashMap<>(builtIn);
            merged.putAll(dynamic);
            return merged.entrySet();
        }
    }

    enum IpFamily {
        IPV4("IPv4", "ipv4"),
        IPV6("IPv6", "ipv6"),
        UNKNOWN("Public", "public");

        private final String label;
        private final String linkLabel;

        IpFamily(String label, String linkLabel) {
            this.label = label;
            this.linkLabel = linkLabel;
        }

        String label() {
            return label;
        }

        String linkLabel() {
            return linkLabel;
        }
    }

    record PublicHost(String host, IpFamily family) {
    }

    enum ProxyTransport {
        ABRIDGED(TRANSPORT_ABRIDGED, RPC_FLAG_ABRIDGED),
        INTERMEDIATE(TAG_INTERMEDIATE, RPC_FLAG_INTERMEDIATE),
        PADDED_INTERMEDIATE(TRANSPORT_HEADER, RPC_FLAG_PAD | RPC_FLAG_INTERMEDIATE);

        private final byte[] telegramHeader;
        private final int middleProxyFlag;

        ProxyTransport(byte[] telegramHeader, int middleProxyFlag) {
            this.telegramHeader = telegramHeader;
            this.middleProxyFlag = middleProxyFlag;
        }

        byte[] telegramHeader() {
            return telegramHeader;
        }

        int middleProxyFlag() {
            return middleProxyFlag;
        }
    }

    enum ProxyMode {
        CLASSIC("classic", TAG_INTERMEDIATE, ""),
        SECURE("secure", TRANSPORT_HEADER, "dd"),
        TLS("tls", TRANSPORT_HEADER, "ee");

        private final String configValue;
        private final byte[] telegramTransportHeader;
        private final String linkPrefix;

        ProxyMode(String configValue, byte[] telegramTransportHeader, String linkPrefix) {
            this.configValue = configValue;
            this.telegramTransportHeader = telegramTransportHeader;
            this.linkPrefix = linkPrefix;
        }

        String configValue() {
            return configValue;
        }

        byte[] telegramTransportHeader() {
            return telegramTransportHeader;
        }

        String linkPrefix() {
            return linkPrefix;
        }

        private static boolean hasTransportTag(byte[] decodedInit, byte[] expectedTag) {
            return decodedInit[56] == expectedTag[0]
                    && decodedInit[57] == expectedTag[1]
                    && decodedInit[58] == expectedTag[2]
                    && decodedInit[59] == expectedTag[3];
        }

    }

    record Modes(boolean classic, boolean secure, boolean tls) {
        List<ProxyMode> enabledModes() {
            List<ProxyMode> out = new ArrayList<>();
            if (classic) {
                out.add(ProxyMode.CLASSIC);
            }
            if (secure) {
                out.add(ProxyMode.SECURE);
            }
            if (tls) {
                out.add(ProxyMode.TLS);
            }
            return out;
        }

        ProxyTransport transport(byte[] decodedInit, boolean fakeTls) {
            if (ProxyMode.hasTransportTag(decodedInit, TRANSPORT_HEADER)) {
                if (fakeTls) {
                    return tls ? ProxyTransport.PADDED_INTERMEDIATE : null;
                }
                return secure ? ProxyTransport.PADDED_INTERMEDIATE : null;
            }
            if (!fakeTls && classic && ProxyMode.hasTransportTag(decodedInit, TAG_INTERMEDIATE)) {
                return ProxyTransport.INTERMEDIATE;
            }
            if (!fakeTls && classic && ProxyMode.hasTransportTag(decodedInit, TAG_ABRIDGED)) {
                return ProxyTransport.ABRIDGED;
            }
            return null;
        }

    }

    record Config(
            int listenPort,
            List<PublicHost> publicHosts,
            byte[] secret,
            DcMaps dcMaps,
            int connectTimeoutMillis,
            boolean logAcceptedConnections,
            boolean logRejectedConnections,
            String tlsDomain,
            Modes modes,
            byte[] adTag,
            MiddleProxyState middleProxyState,
            boolean generateSecretOnly
    ) {
        static Config parse(String[] args) {
            Map<String, List<String>> options = parseOptions(args);
            if (options.containsKey("help")) {
                printHelpAndExit(0);
            }
            if (options.containsKey("generate-secret")) {
                return new Config(443, List.of(new PublicHost("127.0.0.1", IpFamily.IPV4)), new byte[16],
                        new DcMaps(Collections.emptyMap(), Collections.emptyMap()),
                        5000, true, true, "", new Modes(false, true, false), null, null, true);
            }

            String configPath = first(options, "config", envOrDefault("MTPROXY_CONFIG", "mtproxy.properties"));
            Properties fileConfig = loadFileConfig(configPath);

            String secretText = optionEnvProperty(options, fileConfig, "secret", "MTPROXY_SECRET", "secret", null);
            if (secretText == null || secretText.isBlank()) {
                System.err.println("missing secret; set it in mtproxy.properties or pass --secret");
                printHelpAndExit(2);
            }

            int listenPort = parseInt(optionEnvProperty(options, fileConfig, "port", "MTPROXY_PORT", "port", envOrDefault("SERVER_PORT", "443")), "port");
            List<PublicHost> publicHosts = resolvePublicHosts();
            int timeout = parseInt(optionEnvProperty(options, fileConfig, "connect-timeout", "MTPROXY_CONNECT_TIMEOUT", "connectTimeoutMillis", "5000"),
                    "connect-timeout");
            boolean logAccepted = parseBoolean(optionEnvProperty(options, fileConfig, "log-accepted", "MTPROXY_LOG_ACCEPTED", "logAcceptedConnections", "true"),
                    "log-accepted");
            boolean logRejected = parseBoolean(optionEnvProperty(options, fileConfig, "log-rejected", "MTPROXY_LOG_REJECTED", "logRejectedConnections", "true"),
                    "log-rejected");
            String tlsDomain = tlsDomain(options, fileConfig);
            Modes modes = parseModes(options, fileConfig);
            if (modes.tls() && tlsDomain.isBlank()) {
                throw new IllegalArgumentException("TLS_DOMAIN is required when tls=true");
            }
            DcMaps dcMaps = defaultDcMaps();
            byte[] adTag = parseAdTag(optionEnvProperty(options, fileConfig, "ad-tag", "MTPROXY_AD_TAG", "AD_TAG", ""));
            MiddleProxyState middleProxyState = adTag == null ? null : MiddleProxyState.load(timeout);

            return new Config(listenPort, publicHosts, parseSecret(secretText),
                    dcMaps, timeout, logAccepted, logRejected, tlsDomain, modes, adTag, middleProxyState, false);
        }

        String publicSecret(ProxyMode mode) {
            String raw = Hex.encode(secret);
            if (mode == ProxyMode.CLASSIC) {
                return raw;
            }
            if (mode == ProxyMode.SECURE) {
                return "dd" + raw;
            }
            return "ee" + raw + Hex.encode(tlsDomain.trim().getBytes(StandardCharsets.UTF_8));
        }

        private static Modes parseModes(Map<String, List<String>> options, Properties properties) {
            boolean classic = parseBoolean(optionEnvProperty(options, properties, "classic", "MTPROXY_CLASSIC", "classic", "false"), "classic");
            boolean secure = parseBoolean(optionEnvProperty(options, properties, "secure", "MTPROXY_SECURE", "secure", "false"), "secure");
            boolean tls = parseBoolean(optionEnvProperty(options, properties, "tls", "MTPROXY_TLS", "tls", "true"), "tls");
            if (!classic && !secure && !tls) {
                throw new IllegalArgumentException("at least one mode must be enabled: classic, secure, or tls");
            }
            return new Modes(classic, secure, tls);
        }

        private static String tlsDomain(Map<String, List<String>> options, Properties properties) {
            String optionValue = first(options, "tls-domain", null);
            if (optionValue != null) {
                return optionValue.trim();
            }
            String envValue = System.getenv("TLS_DOMAIN");
            if (envValue != null) {
                return envValue.trim();
            }
            return properties.getProperty("TLS_DOMAIN", "www.cloudflare.com").trim();
        }

        private static byte[] parseAdTag(String text) {
            if (text == null || text.isBlank()) {
                return null;
            }
            String normalized = text.trim().toLowerCase(Locale.ROOT);
            if (normalized.startsWith("0x")) {
                normalized = normalized.substring(2);
            }
            byte[] tag = Hex.decode(normalized);
            if (tag.length != 16) {
                throw new IllegalArgumentException("AD_TAG must be 16 bytes hex");
            }
            boolean allZero = true;
            for (byte b : tag) {
                if (b != 0) {
                    allZero = false;
                    break;
                }
            }
            if (allZero) {
                throw new IllegalArgumentException("AD_TAG must not be all zero bytes");
            }
            return tag;
        }

        private static Map<String, List<String>> parseOptions(String[] args) {
            Map<String, List<String>> options = new LinkedHashMap<>();
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if (!arg.startsWith("--")) {
                    throw new IllegalArgumentException("unexpected argument: " + arg);
                }
                String key;
                String value;
                int eq = arg.indexOf('=');
                if (eq >= 0) {
                    key = arg.substring(2, eq);
                    value = arg.substring(eq + 1);
                } else {
                    key = arg.substring(2);
                    if (key.equals("help") || key.equals("generate-secret")) {
                        value = "true";
                    } else {
                        if (i + 1 >= args.length) {
                            throw new IllegalArgumentException("missing value for --" + key);
                        }
                        value = args[++i];
                    }
                }
                if (!OPTION_NAMES.contains(key)) {
                    throw new IllegalArgumentException("unknown option: --" + key);
                }
                options.computeIfAbsent(key, ignored -> new ArrayList<>()).add(value);
            }
            return options;
        }

        private static Properties loadFileConfig(String pathText) {
            Properties properties = new Properties();
            Path path = Path.of(pathText);
            if (!Files.isRegularFile(path)) {
                throw new IllegalArgumentException("config file does not exist: " + path);
            }
            try (InputStream in = Files.newInputStream(path)) {
                properties.load(in);
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to read config file: " + path, e);
            }
            return properties;
        }

        private static String optionEnvProperty(
                Map<String, List<String>> options,
                Properties properties,
                String optionName,
                String envName,
                String propertyName,
                String fallback
        ) {
            String optionValue = first(options, optionName, null);
            if (optionValue != null && !optionValue.isBlank()) {
                return optionValue;
            }
            String envValue = System.getenv(envName);
            if (envValue != null && !envValue.isBlank()) {
                return envValue;
            }
            String propertyValue = properties.getProperty(propertyName);
            if (propertyValue != null && !propertyValue.isBlank()) {
                return propertyValue.trim();
            }
            return fallback;
        }

        private static List<PublicHost> resolvePublicHosts() {
            List<PublicHost> hosts = new ArrayList<>();
            detectPublicHost(IpFamily.IPV4, PUBLIC_IPV4_ENDPOINTS).ifPresent(hosts::add);
            detectPublicHost(IpFamily.IPV6, PUBLIC_IPV6_ENDPOINTS).ifPresent(hosts::add);
            if (!hosts.isEmpty()) {
                return hosts;
            }

            String serverIp = envOrDefault("SERVER_IP", envOrDefault("P_SERVER_IP", ""));
            if (isUsablePublicHost(serverIp) && !isLocalOrWildcardHost(serverIp)) {
                return List.of(new PublicHost(serverIp, inferIpFamily(serverIp)));
            }

            return List.of(new PublicHost("127.0.0.1", IpFamily.IPV4));
        }

        private static java.util.Optional<PublicHost> detectPublicHost(IpFamily family, List<String> endpoints) {
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(3))
                    .build();
            for (String endpoint : endpoints) {
                try {
                    HttpRequest request = HttpRequest.newBuilder(URI.create(endpoint))
                            .timeout(Duration.ofSeconds(4))
                            .header("User-Agent", "jmtproxy/0.1")
                            .GET()
                            .build();
                    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    if (response.statusCode() < 200 || response.statusCode() >= 300) {
                        continue;
                    }
                    String host = extractDetectedHost(response.body(), family);
                    if (host != null) {
                        return java.util.Optional.of(new PublicHost(host, family));
                    }
                } catch (IOException e) {
                    // Try the next endpoint.
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (RuntimeException e) {
                    // Try the next endpoint.
                }
            }
            return java.util.Optional.empty();
        }

        private static boolean isLocalOrWildcardHost(String value) {
            if (value == null || value.isBlank()) {
                return true;
            }
            String normalized = value.trim().toLowerCase(Locale.ROOT);
            return normalized.equals("your.domain.com")
                    || normalized.equals("localhost")
                    || normalized.equals("127.0.0.1")
                    || normalized.equals("0.0.0.0")
                    || normalized.equals("::");
        }

        private static String firstLine(String value) {
            int newline = value.indexOf('\n');
            return newline >= 0 ? value.substring(0, newline) : value;
        }

        private static String extractDetectedHost(String body, IpFamily family) {
            if (body == null || body.isBlank()) {
                return null;
            }
            if (family == IpFamily.IPV4) {
                Matcher matcher = IPV4_PATTERN.matcher(body);
                while (matcher.find()) {
                    String candidate = matcher.group();
                    if (isIpv4(candidate)) {
                        return candidate;
                    }
                }
                return null;
            }
            if (family == IpFamily.IPV6) {
                for (String token : body.split("[\\s,;]+")) {
                    String candidate = token.trim();
                    if (candidate.startsWith("[") && candidate.endsWith("]")) {
                        candidate = candidate.substring(1, candidate.length() - 1);
                    }
                    if (isIpv6(candidate)) {
                        return candidate;
                    }
                }
                return null;
            }
            String host = firstLine(body).trim();
            return isUsablePublicHost(host) ? host : null;
        }

        private static boolean isUsablePublicHost(String value) {
            if (value == null) {
                return false;
            }
            String host = value.trim();
            if (host.isEmpty() || host.length() > 253 || host.contains(" ") || host.contains("\t")) {
                return false;
            }
            return host.matches("[A-Za-z0-9:.\\-]+");
        }

        private static boolean isUsableDetectedHost(String value, IpFamily family) {
            if (!isUsablePublicHost(value)) {
                return false;
            }
            if (family == IpFamily.IPV6) {
                return isIpv6(value);
            }
            if (family == IpFamily.IPV4) {
                return isIpv4(value);
            }
            return isIpv4(value) || isIpv6(value);
        }

        private static IpFamily inferIpFamily(String value) {
            if (isIpv4(value)) {
                return IpFamily.IPV4;
            }
            if (isIpv6(value)) {
                return IpFamily.IPV6;
            }
            return IpFamily.UNKNOWN;
        }

        private static boolean isIpv4(String value) {
            String[] parts = value.trim().split("\\.");
            if (parts.length != 4) {
                return false;
            }
            for (String part : parts) {
                try {
                    int number = Integer.parseInt(part);
                    if (number < 0 || number > 255 || !String.valueOf(number).equals(part)) {
                        return false;
                    }
                } catch (NumberFormatException e) {
                    return false;
                }
            }
            return true;
        }

        private static boolean isIpv6(String value) {
            String host = value.trim();
            return host.contains(":") && host.matches("[0-9A-Fa-f:.]+");
        }

        private static DcMaps defaultDcMaps() {
            Map<Integer, List<Endpoint>> v4 = new HashMap<>();
            v4.put(1, List.of(new Endpoint("149.154.175.50", 443)));
            v4.put(2, List.of(new Endpoint("149.154.167.51", 443)));
            v4.put(3, List.of(new Endpoint("149.154.175.100", 443)));
            v4.put(4, List.of(new Endpoint("149.154.167.91", 443)));
            v4.put(5, List.of(new Endpoint("91.108.56.130", 443)));
            v4.put(203, List.of(new Endpoint("91.105.192.100", 443)));

            Map<Integer, List<Endpoint>> v6 = new HashMap<>();
            v6.put(1, List.of(new Endpoint("2001:b28:f23d:f001::a", 443)));
            v6.put(2, List.of(new Endpoint("2001:67c:4e8:f002::a", 443)));
            v6.put(3, List.of(new Endpoint("2001:b28:f23d:f003::a", 443)));
            v6.put(4, List.of(new Endpoint("2001:67c:4e8:f004::a", 443)));
            v6.put(5, List.of(new Endpoint("2001:b28:f23f:f005::a", 443)));
            v6.put(203, List.of(new Endpoint("2a0a:f280:203:a:5000::100", 443)));
            return new DcMaps(new DynamicDcMap(v4), new DynamicDcMap(v6));
        }

        private static byte[] parseSecret(String text) {
            String normalized = text.trim().toLowerCase(Locale.ROOT);
            if (normalized.startsWith("dd") && normalized.length() == 34) {
                normalized = normalized.substring(2);
            }
            if (normalized.startsWith("ee") && normalized.length() >= 34) {
                normalized = normalized.substring(2, 34);
            }
            byte[] secret = Hex.decode(normalized);
            if (secret.length != 16) {
                throw new IllegalArgumentException("secret must be 16 bytes hex, optionally prefixed with dd");
            }
            return secret;
        }

        private static String first(Map<String, List<String>> options, String key, String fallback) {
            List<String> values = options.get(key);
            return values == null || values.isEmpty() ? fallback : values.get(values.size() - 1);
        }

        private static String envOrDefault(String name, String fallback) {
            String value = System.getenv(name);
            return value == null || value.isBlank() ? fallback : value;
        }

        private static boolean hasEnv(String name) {
            String value = System.getenv(name);
            return value != null && !value.isBlank();
        }

        private static int parseInt(String value, String name) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(name + " must be an integer: " + value, e);
            }
        }

        private static boolean parseBoolean(String value, String name) {
            String normalized = value.trim().toLowerCase(Locale.ROOT);
            return switch (normalized) {
                case "true", "yes", "1", "on" -> true;
                case "false", "no", "0", "off" -> false;
                default -> throw new IllegalArgumentException(name + " must be true or false: " + value);
            };
        }

        private static void printHelpAndExit(int status) {
            System.out.println("""
                    Java MTProxy minimal server

                    Options:
                      --generate-secret           Generate a raw and dd-prefixed MTProxy secret
                      --config <path>             Config file path, default mtproxy.properties
                      --secret <hex>              16-byte hex secret, with optional dd prefix
                      --classic <true|false>      Enable classic raw-secret links, default false
                      --secure <true|false>       Enable dd secure links, default false
                      --tls <true|false>          Enable ee FakeTLS links, default true
                      --ad-tag <hex>              Enable Telegram middle proxy AD_TAG, 16-byte hex
                      --port <port>               Bind port, default 443
                      --tls-domain <domain>       FakeTLS SNI/domain, used when tls=true
                      --connect-timeout <ms>      Telegram DC connect timeout, default 5000
                      --log-accepted <true|false> Log successful MTProxy handshakes, default true
                      --log-rejected <true|false> Log rejected/invalid connections, default true

                    Example:
                      java -jar target/jmtproxy-0.1.0.jar --secret dd0123456789abcdef0123456789abcdef --port 8443
                    """);
            System.exit(status);
        }
    }

    static final class Hex {
        private static final char[] CHARS = "0123456789abcdef".toCharArray();

        private Hex() {
        }

        static String encode(byte[] bytes) {
            char[] out = new char[bytes.length * 2];
            for (int i = 0; i < bytes.length; i++) {
                int value = bytes[i] & 0xff;
                out[i * 2] = CHARS[value >>> 4];
                out[i * 2 + 1] = CHARS[value & 0x0f];
            }
            return new String(out);
        }

        static byte[] decode(String hex) {
            if ((hex.length() & 1) != 0) {
                throw new IllegalArgumentException("hex string must have an even length");
            }
            byte[] out = new byte[hex.length() / 2];
            for (int i = 0; i < out.length; i++) {
                int hi = Character.digit(hex.charAt(i * 2), 16);
                int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
                if (hi < 0 || lo < 0) {
                    throw new IllegalArgumentException("invalid hex string");
                }
                out[i] = (byte) ((hi << 4) | lo);
            }
            return out;
        }
    }

    static final class NamedThreadFactory implements ThreadFactory {
        private final String prefix;
        private final AtomicLong nextId = new AtomicLong();

        NamedThreadFactory(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, prefix + "-" + nextId.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }

    static void log(String message) {
        System.out.println(Instant.now() + " " + message);
    }
}
