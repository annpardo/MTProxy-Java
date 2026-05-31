# jmtproxy

[中文说明](README.md)

A small Java Telegram MTProxy server example. It supports classic, `dd` secure, and `ee` FakeTLS modes, plus IPv4/IPv6 public links and Telegram DC forwarding.

> Note: This is not a full replacement for the official MTProxy. It is intended for learning, lab use, and small private deployments. For production use, consider rate limiting, monitoring, IP blocking, and systemd/Docker deployment.

## Features

- Java 17+, no third-party runtime dependencies
- Supports classic raw secret, `dd` secret, and `ee` FakeTLS secret
- Forwards to Telegram DCs according to the DC id in the handshake
- IPv4 clients prefer IPv4 DCs, IPv6 clients prefer IPv6 DCs, with automatic fallback to the other address family
- Uses built-in Telegram direct DC addresses; manual DC configuration is not exposed. DC203/CDN is supplemented from official `getProxyConfig`
- Built-in secret generator

## Pterodactyl

Upload `build/server.jar` as `server.jar` in the panel. Put `mtproxy.properties` in the server root before startup; the server will not start without a config file. Panel-provided `SERVER_PORT` can still be used as the default listen port.

After startup, the server detects public IPv4/IPv6 addresses and prints available Telegram proxy links.

## Options

```text
--generate-secret           Generate raw and dd-prefixed secrets
--config <path>             Config file path, default mtproxy.properties
--secret <hex>              16-byte hex secret, optional dd prefix
--classic <true|false>      Enable classic raw-secret links, default false
--secure <true|false>       Enable dd secure links, default false
--tls <true|false>          Enable ee FakeTLS links, default true
--port <port>               Bind port, default 443
--tls-domain <domain>       FakeTLS SNI/domain, used when tls=true
--connect-timeout <ms>      Telegram DC connect timeout, default 5000
--log-connections <true|false>
                            Log accepted/rejected connections, default false
--stats-print-period-minutes <minutes>
                            Print periodic connection, traffic, and message stats, default 20, 0 disables
```

## Config Fields

```properties
secret=0123456789abcdef0123456789abcdef
classic=false
secure=false
tls=true
TLS_DOMAIN=www.cloudflare.com
AD_TAG=
port=8443
connectTimeoutMillis=5000
logConnections=false
statsPrintPeriodMinutes=20
```

If the example `secret` is still used, the server starts normally but prints a warning and suggests a random replacement secret.

Backend DC addresses are no longer manually configured. This Java implementation uses built-in Telegram direct DC addresses; DC1-5 are static, while DC203/CDN can be supplemented from Telegram's official `getProxyConfig` / `getProxyConfigV6`. If fetching fails, built-in DC203 remains in use.

## Firewall

Allow the configured port in both the cloud security group and the system firewall, for example `8443/tcp`.

On Linux, binding to `443` usually requires root privileges or granting the Java binary permission to bind low ports.

## Verification

The project includes a handshake self-test that does not require JUnit.

```bash
javac -d out $(find src/main/java src/test/java -name '*.java')
java -cp out io.github.example.jmtproxy.HandshakeSelfTest
```

PowerShell:

```powershell
javac -d out (Get-ChildItem src/main/java,src/test/java -Recurse -Filter *.java)
java -cp out io.github.example.jmtproxy.HandshakeSelfTest
```
