package io.github.example.jmtproxy;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;

public final class HandshakeSelfTest {
    private HandshakeSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        byte[] secret = JMtProxy.Hex.decode("0123456789abcdef0123456789abcdef");
        byte[] plainInit = new byte[64];
        new Random(42).nextBytes(plainInit);
        Arrays.fill(plainInit, 56, 60, (byte) 0xdd);
        plainInit[60] = 2;
        plainInit[61] = 0;

        byte[] encryptedInit = plainInit.clone();
        Cipher clientEncrypt = cipher(Cipher.ENCRYPT_MODE, plainInit, secret);
        byte[] encryptedAll = clientEncrypt.update(plainInit);
        System.arraycopy(encryptedAll, 56, encryptedInit, 56, 8);

        JMtProxy.Modes modes = new JMtProxy.Modes(false, true, false);
        JMtProxy.Handshake handshake = JMtProxy.Handshake.read(new ByteArrayInputStream(encryptedInit), secret, modes, false);
        if (handshake.dcId() != 2) {
            throw new AssertionError("dc id mismatch");
        }

        byte[] payload = "hello mtproxy".getBytes();
        byte[] encryptedPayload = clientEncrypt.update(payload);
        byte[] decodedPayload = handshake.clientToProxyCipher().update(encryptedPayload);
        if (!Arrays.equals(payload, decodedPayload)) {
            throw new AssertionError("client decrypt stream mismatch");
        }

        byte[] response = "telegram response".getBytes();
        Cipher clientDecrypt = cipher(Cipher.DECRYPT_MODE, reverse(plainInit), secret);
        byte[] encryptedResponse = handshake.proxyToClientCipher().update(response);
        byte[] decodedResponse = clientDecrypt.update(encryptedResponse);
        if (!Arrays.equals(response, decodedResponse)) {
            throw new AssertionError("server encrypt stream mismatch");
        }

        JMtProxy.Config config = new JMtProxy.Config(
                443,
                List.of(new JMtProxy.PublicHost("2001:db8::1", JMtProxy.IpFamily.IPV6)),
                secret,
                new JMtProxy.DcMaps(
                        Map.of(2, List.of(new JMtProxy.Endpoint("127.0.0.1", 443))),
                        Map.of(2, List.of(new JMtProxy.Endpoint("2001:db8::2", 443)))
                ),
                5000,
                false,
                20,
                "www.cloudflare.com",
                new JMtProxy.Modes(false, true, false),
                null,
                null,
                false
        );
        List<JMtProxy.Endpoint> ipv6Preferred = config.dcMaps().endpoints(2, JMtProxy.IpFamily.IPV6);
        if (!ipv6Preferred.get(0).host().contains(":") || ipv6Preferred.size() != 2) {
            throw new AssertionError("IPv6 endpoint preference mismatch");
        }

        List<JMtProxy.Endpoint> parsedCdn = JMtProxy.Dc203Updater.parseDc203Config("""
                proxy_for 1 149.154.175.50:8888;
                proxy_for 203 91.105.192.110:443;
                proxy_for -203 91.105.192.111:443;
                """, JMtProxy.IpFamily.IPV4);
        if (parsedCdn.size() != 2 || !parsedCdn.get(0).host().equals("91.105.192.110")) {
            throw new AssertionError("DC203 public config parsing mismatch");
        }
        List<JMtProxy.Endpoint> parsedCdnV6 = JMtProxy.Dc203Updater.parseDc203Config(
                "proxy_for 203 [2a0a:f280:203:a:5000::110]:443;",
                JMtProxy.IpFamily.IPV6
        );
        if (parsedCdnV6.size() != 1 || !parsedCdnV6.get(0).host().contains(":")) {
            throw new AssertionError("DC203 IPv6 public config parsing mismatch");
        }

        var middleV4 = JMtProxy.MiddleProxyState.parseMiddleProxyConfig("""
                proxy_for 1 149.154.175.50:8888;
                proxy_for 203 91.105.192.110:8888;
                """, JMtProxy.IpFamily.IPV4);
        if (middleV4.size() != 2 || !middleV4.containsKey(203)) {
            throw new AssertionError("middle proxy config parsing mismatch");
        }
        JMtProxy.MiddleProxyState fallbackMiddle = JMtProxy.MiddleProxyState.load(1);
        if (fallbackMiddle.secret().length < 32
                || fallbackMiddle.endpoints(5, JMtProxy.IpFamily.IPV4).isEmpty()
                || fallbackMiddle.endpoints(1, JMtProxy.IpFamily.IPV6).isEmpty()) {
            throw new AssertionError("built-in middle proxy fallback mismatch");
        }

        byte[] adTag = JMtProxy.Hex.decode("0123456789abcdef0123456789abcdef");
        JMtProxy.MiddleFrameCodec codec = new JMtProxy.MiddleFrameCodec(null, null, 0, 0);
        ByteArrayOutputStream middleOut = new ByteArrayOutputStream();
        JMtProxy.MiddleRequestTransform requestTransform = new JMtProxy.MiddleRequestTransform(
                codec,
                middleOut,
                JMtProxy.ProxyTransport.INTERMEDIATE,
                new byte[20],
                new byte[20],
                7L,
                adTag
        );
        requestTransform.apply(new JMtProxy.ClientFrameWriter(JMtProxy.ProxyTransport.INTERMEDIATE)
                .writeData("hello".getBytes(), false));
        byte[] requestBytes = middleOut.toByteArray();
        byte[] requestPayload = new JMtProxy.MiddleFrameCodec(null, null, 0, 0).readFrame(new ByteArrayInputStream(requestBytes));
        if (le32(requestPayload, 0) != 0x36cef1ee) {
            throw new AssertionError("RPC_PROXY_REQ type mismatch");
        }
        if (le32(requestPayload, 4) != (0x00001000 | 0x00020000 | 0x00000008 | 0x20000000)) {
            throw new AssertionError("RPC_PROXY_REQ flags mismatch");
        }

        int closedPort = allocateUnusedPort();
        try (ServerSocket server = new ServerSocket(0)) {
            Thread accepter = new Thread(() -> {
                try (Socket accepted = server.accept()) {
                    byte[] backendHandshake = accepted.getInputStream().readNBytes(64);
                    if (backendHandshake.length != 64) {
                        throw new AssertionError("Telegram backend handshake length mismatch");
                    }
                    if (backendHandshake[56] == (byte) 0xdd
                            && backendHandshake[57] == (byte) 0xdd
                            && backendHandshake[58] == (byte) 0xdd
                            && backendHandshake[59] == (byte) 0xdd) {
                        throw new AssertionError("Telegram backend handshake transport header was not obfuscated");
                    }
                    accepted.getOutputStream().write(1);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            accepter.start();
            List<JMtProxy.Endpoint> fallbackEndpoints = List.of(
                    new JMtProxy.Endpoint("127.0.0.1", closedPort),
                    new JMtProxy.Endpoint("127.0.0.1", server.getLocalPort())
            );
            try (JMtProxy.ConnectedTelegram connectedTelegram = JMtProxy.ProxyConnection.connectTelegram(fallbackEndpoints, 1000, 2)) {
                Socket connected = connectedTelegram.socket();
                connected.setSoTimeout(1000);
                if (connected.getInputStream().read() != 1) {
                    throw new AssertionError("Telegram endpoint fallback stream mismatch");
                }
            }
            accepter.join(1000);
        }

        System.out.println("HandshakeSelfTest OK");
    }

    private static int allocateUnusedPort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static int le32(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff)
                | ((bytes[offset + 1] & 0xff) << 8)
                | ((bytes[offset + 2] & 0xff) << 16)
                | ((bytes[offset + 3] & 0xff) << 24);
    }

    private static Cipher cipher(int mode, byte[] init, byte[] secret) throws Exception {
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
}
