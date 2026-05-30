# jmtproxy

一个尽量小的 Java 版 Telegram MTProxy 服务端示例。当前实现支持 classic、`dd` secure 和 `ee` FakeTLS 三种模式，并支持 IPv4/IPv6 入口与后端 DC 转发。

> 注意：这不是官方 MTProxy 的完整替代品。它适合学习、内网实验、小规模自用；生产环境请额外考虑限速、监控、IP 封禁和 systemd/Docker 部署。

## 功能

- Java 17+，无第三方运行时依赖
- 支持 classic raw secret、`dd` secret 和 `ee` FakeTLS secret
- 按握手里的 DC id 转发到 Telegram DC
- IPv4 客户端优先连接 Telegram IPv4 DC，IPv6 客户端优先连接 Telegram IPv6 DC，首选地址族失败时自动尝试备用地址族
- 使用内置 Telegram 直连 DC 地址表，不开放手动 DC 配置；DC203/CDN 会参考官方 `getProxyConfig` 自动补充
- 内置 secret 生成命令

## 编译

如果有 Maven：

```bash
mvn package
```

没有 Maven 时也可以直接用 JDK 编译运行：

```bash
javac -d out $(find src/main/java -name '*.java')
java -cp out io.github.example.jmtproxy.JMtProxy --generate-secret
```

Windows PowerShell：

```powershell
javac -d out (Get-ChildItem src/main/java -Recurse -Filter *.java)
java -cp out io.github.example.jmtproxy.JMtProxy --generate-secret
```

## 运行

先生成 secret：

```bash
java -jar target/jmtproxy-0.1.0.jar --generate-secret
```

把生成的 `dd...` secret 写入根目录的 `mtproxy.properties`：

```properties
secret=dd0123456789abcdef0123456789abcdef
classic=false
secure=false
tls=true
TLS_DOMAIN=www.cloudflare.com
port=8443
connectTimeoutMillis=5000
logAcceptedConnections=true
logRejectedConnections=true
```

`secret` 可以写 `dd0123...`、`ee0123...`，也可以只写 `0123...`。程序内部会取 16 字节 raw secret。

仓库里提供了 `mtproxy.properties` 示例配置。下载代码后直接修改这个文件即可运行；提交公开仓库前不要把自己的真实 secret 提交上去。

三个模式开关决定输出和接受哪些链接，可以只开一个，也可以同时开多个：

```text
classic=true  输出 raw secret，只接受 efefefef / eeeeeeee
secure=true   输出 dd + secret，只接受非 FakeTLS 的 dddddddd
tls=true      输出 ee + secret + TLS_DOMAIN_HEX，只接受 FakeTLS 里的 dddddddd
```

`TLS_DOMAIN` 只在 `tls=true` 时使用，修改这个值即可修改 TLS 混淆域名。

程序启动时会自动检测 IPv4 和 IPv6 公网地址。检测到两个地址时会同时监听 IPv4/IPv6 并输出两条 Telegram 链接；只检测到一个地址时只输出对应链接。

启动代理时默认会读取 `mtproxy.properties`。如果这个文件不存在，程序会自动生成一个默认配置和随机 secret：

```bash
java -jar target/jmtproxy-0.1.0.jar
```

直接用 JDK 编译的版本：

```bash
java -cp out io.github.example.jmtproxy.JMtProxy
```

修改端口或 secret 后，重启 Java 进程即可生效。

也可以指定另一个配置文件：

```bash
java -jar target/jmtproxy-0.1.0.jar --config /etc/jmtproxy/mtproxy.properties
```

命令行参数只保留 `--secret` 和 `--port` 等基础覆盖，适合临时调试：

```bash
java -jar target/jmtproxy-0.1.0.jar \
  --secret dd0123456789abcdef0123456789abcdef \
  --port 8443
```

启动后控制台会打印 `tg://proxy?...` 链接。

## Pterodactyl

面板里可以把 `build/server.jar` 上传成 `server.jar`。如果服务器根目录没有 `mtproxy.properties`，程序第一次启动会自动创建它，并尽量使用面板注入的 `SERVER_PORT` 作为监听端口。

第一次启动后，程序会自动检测公网 IPv4/IPv6，并打印可用的 Telegram 链接。

## 参数

```text
--generate-secret           生成 raw secret 和 dd-prefixed secret
--config <path>             配置文件路径，默认 mtproxy.properties
--secret <hex>              16 字节 hex secret，可带 dd 前缀
--classic <true|false>     是否启用 classic raw-secret 链接，默认 false
--secure <true|false>      是否启用 dd secure 链接，默认 false
--tls <true|false>         是否启用 ee FakeTLS 链接，默认 true
--port <port>               监听端口，默认 443
--tls-domain <domain>       FakeTLS SNI/domain，在 tls=true 时使用
--connect-timeout <ms>      连接 Telegram DC 超时，默认 5000
--log-accepted <true|false> 记录成功握手，默认 true
--log-rejected <true|false> 记录失败连接，默认 true
```

配置文件字段：

```properties
secret=dd0123456789abcdef0123456789abcdef
classic=false
secure=false
tls=true
TLS_DOMAIN=www.cloudflare.com
port=8443
connectTimeoutMillis=5000
logAcceptedConnections=true
logRejectedConnections=true
```

后端 DC 地址不再手动配置。当前 Java 实现使用内置 Telegram 直连静态 DC 地址表；DC1-5 不做动态更新，DC203/CDN 会参考 Telegram 官方 `getProxyConfig` / `getProxyConfigV6` 自动补充，失败时继续使用内置 DC203。

## 服务器放行

云服务器安全组和系统防火墙都要放行你设置的端口，例如 `8443/tcp`。

Linux 上如果想监听 `443`，通常需要 root 权限，或者给 Java 二进制授予绑定低端口能力。

## 验证

项目带了一个无需 JUnit 的握手自测：

```bash
javac -d out $(find src/main/java src/test/java -name '*.java')
java -cp out io.github.example.jmtproxy.HandshakeSelfTest
```

PowerShell：

```powershell
javac -d out (Get-ChildItem src/main/java,src/test/java -Recurse -Filter *.java)
java -cp out io.github.example.jmtproxy.HandshakeSelfTest
```
