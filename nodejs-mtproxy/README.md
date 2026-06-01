# Node.js MTProxy

这是一个最小可用的 Node.js 版 Telegram MTProxy 服务端示例，使用 Node.js 内置模块实现，不需要安装 npm 依赖。

This is a minimal Node.js Telegram MTProxy server example implemented with built-in Node.js modules only. No npm dependencies are required.

## 支持 / Supported

- classic raw secret
- `dd` secure mode
- `ee` FakeTLS mode
- IPv4/IPv6 public link generation
- Static Telegram DC forwarding
- Periodic traffic stats

## 暂不支持 / Not Supported Yet

- AD_TAG / Telegram middle proxy
- Dynamic DC updates

## 运行 / Run

```bash
node server.js
```

程序默认读取当前目录的 `mtproxy.properties`。如果配置文件不存在，程序不会启动。

The server reads `mtproxy.properties` from the current directory by default. It will not start if the config file is missing.

生成 secret / Generate secret:

```bash
node server.js --generate-secret
```

指定配置文件 / Use another config file:

```bash
node server.js --config /path/to/mtproxy.properties
```
