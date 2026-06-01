'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const { once } = require('node:events');

const HANDSHAKE_SIZE = 64;
const BUFFER_SIZE = 32 * 1024;
const TLS_MAX_CHUNK_SIZE = 16 * 1024;
const TAG_ABRIDGED = Buffer.from('efefefef', 'hex');
const TAG_INTERMEDIATE = Buffer.from('eeeeeeee', 'hex');
const TRANSPORT_HEADER = Buffer.from('dddddddd', 'hex');
const TLS_SERVER_FIRST_PART = Buffer.from(
  '1603030000020000000303000000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);
const TLS_SERVER_SECOND_PART = Buffer.from(
  '130100002e00330024001d00200000000000000000000000000000000000000000000000000000000000000000002b000203041403030001011703030000',
  'hex'
);
const PUBLIC_IPV4_ENDPOINTS = ['https://api.ipify.org', 'https://ifconfig.me/ip'];
const PUBLIC_IPV6_ENDPOINTS = ['https://api6.ipify.org', 'https://ifconfig.me/ip'];
const DEFAULT_SECRETS = new Set([
  '00000000000000000000000000000000',
  '00000000000000000000000000000001',
  '0123456789abcdef0123456789abcdef'
]);

const DC_V4 = new Map([
  [1, [{ host: '149.154.175.50', port: 443 }]],
  [2, [{ host: '149.154.167.51', port: 443 }]],
  [3, [{ host: '149.154.175.100', port: 443 }]],
  [4, [{ host: '149.154.167.91', port: 443 }]],
  [5, [{ host: '91.108.56.130', port: 443 }]],
  [203, [{ host: '91.105.192.100', port: 443 }]]
]);

const DC_V6 = new Map([
  [1, [{ host: '2001:b28:f23d:f001::a', port: 443 }]],
  [2, [{ host: '2001:67c:4e8:f002::a', port: 443 }]],
  [3, [{ host: '2001:b28:f23d:f003::a', port: 443 }]],
  [4, [{ host: '2001:67c:4e8:f004::a', port: 443 }]],
  [5, [{ host: '2001:b28:f23f:f005::a', port: 443 }]],
  [203, [{ host: '2a0a:f280:203:a:5000::100', port: 443 }]]
]);

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.has('generate-secret')) {
    const secret = randomSecretHex();
    console.log(`Raw secret: ${secret}`);
    console.log(`MTProxy dd secret: dd${secret}`);
    return;
  }

  loadConfig(args).then((config) => {
    const server = new MtProxyServer(config);
    return server.start();
  }).catch((error) => {
    console.error(error.message || error);
    process.exitCode = 1;
  });
}

function parseArgs(argv) {
  const out = new Map();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      throw new Error(`unexpected argument: ${arg}`);
    }
    const eq = arg.indexOf('=');
    if (eq >= 0) {
      out.set(arg.slice(2, eq), arg.slice(eq + 1));
      continue;
    }
    const key = arg.slice(2);
    if (key === 'generate-secret' || key === 'help') {
      out.set(key, 'true');
      continue;
    }
    if (i + 1 >= argv.length) {
      throw new Error(`missing value for --${key}`);
    }
    out.set(key, argv[++i]);
  }
  if (out.has('help')) {
    printHelp();
    process.exit(0);
  }
  return out;
}

async function loadConfig(args) {
  const configPath = args.get('config') || process.env.MTPROXY_CONFIG || 'mtproxy.properties';
  if (!fs.existsSync(configPath)) {
    throw new Error(`config file does not exist: ${configPath}`);
  }
  const properties = parseProperties(fs.readFileSync(configPath, 'utf8'));
  const secretText = optionEnvProperty(args, properties, 'secret', 'MTPROXY_SECRET', 'secret', null);
  if (!secretText) {
    throw new Error('missing secret; set it in mtproxy.properties or pass --secret');
  }
  const secret = parseSecret(secretText);
  const port = parseIntStrict(optionEnvProperty(args, properties, 'port', 'MTPROXY_PORT', 'port', process.env.SERVER_PORT || '443'), 'port');
  const connectTimeoutMillis = parseIntStrict(optionEnvProperty(args, properties, 'connect-timeout', 'MTPROXY_CONNECT_TIMEOUT', 'connectTimeoutMillis', '5000'), 'connect-timeout');
  const classic = parseBoolean(optionEnvProperty(args, properties, 'classic', 'MTPROXY_CLASSIC', 'classic', 'false'), 'classic');
  const secure = parseBoolean(optionEnvProperty(args, properties, 'secure', 'MTPROXY_SECURE', 'secure', 'false'), 'secure');
  const tls = parseBoolean(optionEnvProperty(args, properties, 'tls', 'MTPROXY_TLS', 'tls', 'true'), 'tls');
  const tlsDomain = optionEnvProperty(args, properties, 'tls-domain', 'TLS_DOMAIN', 'TLS_DOMAIN', 'www.cloudflare.com').trim();
  const logConnections = parseBoolean(optionEnvProperty(args, properties, 'log-connections', 'MTPROXY_LOG_CONNECTIONS', 'logConnections', 'false'), 'log-connections');
  const statsPrintPeriodMinutes = parseIntStrict(optionEnvProperty(args, properties, 'stats-print-period-minutes', 'MTPROXY_STATS_PRINT_PERIOD_MINUTES', 'statsPrintPeriodMinutes', '20'), 'stats-print-period-minutes');
  if (!classic && !secure && !tls) {
    throw new Error('at least one mode must be enabled: classic, secure, or tls');
  }
  if (tls && !tlsDomain) {
    throw new Error('TLS_DOMAIN is required when tls=true');
  }
  if (statsPrintPeriodMinutes < 0) {
    throw new Error('stats-print-period-minutes must be >= 0');
  }

  const publicHosts = await resolvePublicHosts();
  if (publicHosts.length === 0) {
    publicHosts.push({ host: '127.0.0.1', family: 'ipv4' });
  }

  return {
    port,
    secret,
    classic,
    secure,
    tls,
    tlsDomain,
    connectTimeoutMillis,
    logConnections,
    statsPrintPeriodMinutes,
    publicHosts
  };
}

function parseProperties(text) {
  const out = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('!')) {
      continue;
    }
    const idx = line.search(/[:=]/);
    if (idx < 0) {
      continue;
    }
    out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return out;
}

function optionEnvProperty(args, properties, optionName, envName, propertyName, fallback) {
  const optionValue = args.get(optionName);
  if (optionValue) return optionValue;
  const envValue = process.env[envName];
  if (envValue) return envValue;
  const propertyValue = properties[propertyName];
  if (propertyValue) return propertyValue;
  return fallback;
}

function parseSecret(text) {
  let normalized = text.trim().toLowerCase();
  if (normalized.startsWith('dd') && normalized.length === 34) {
    normalized = normalized.slice(2);
  }
  if (normalized.startsWith('ee') && normalized.length >= 34) {
    normalized = normalized.slice(2, 34);
  }
  if (!/^[0-9a-f]{32}$/.test(normalized)) {
    throw new Error('secret must be 16 bytes hex, optionally prefixed with dd/ee');
  }
  return Buffer.from(normalized, 'hex');
}

function parseBoolean(value, name) {
  const normalized = String(value).trim().toLowerCase();
  if (['true', 'yes', '1', 'on'].includes(normalized)) return true;
  if (['false', 'no', '0', 'off'].includes(normalized)) return false;
  throw new Error(`${name} must be true or false: ${value}`);
}

function parseIntStrict(value, name) {
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isInteger(parsed) || String(parsed) !== String(value).trim()) {
    throw new Error(`${name} must be an integer: ${value}`);
  }
  return parsed;
}

async function resolvePublicHosts() {
  const hosts = [];
  const ipv4 = await detectPublicHost('ipv4', PUBLIC_IPV4_ENDPOINTS);
  const ipv6 = await detectPublicHost('ipv6', PUBLIC_IPV6_ENDPOINTS);
  if (ipv4) hosts.push({ host: ipv4, family: 'ipv4' });
  if (ipv6) hosts.push({ host: ipv6, family: 'ipv6' });
  return hosts;
}

async function detectPublicHost(family, endpoints) {
  for (const endpoint of endpoints) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);
      const response = await fetch(endpoint, { signal: controller.signal });
      clearTimeout(timer);
      const text = (await response.text()).trim();
      if (family === 'ipv4' && isIpv4(text)) return text;
      if (family === 'ipv6' && isIpv6(text)) return text;
    } catch {
      // Try the next endpoint.
    }
  }
  return null;
}

class MtProxyServer {
  constructor(config) {
    this.config = config;
    this.stats = new ProxyStats();
    this.servers = [];
  }

  async start() {
    this.printStartupSummary();
    this.startStatsPrinter();
    await this.bindServers();
    process.on('SIGINT', () => this.close());
    process.on('SIGTERM', () => this.close());
    process.stdin.setEncoding('utf8');
    process.stdin.resume();
    process.stdin.on('data', (data) => {
      const command = data.trim().toLowerCase();
      if (['stop', 'shutdown', 'exit', 'quit'].includes(command)) {
        this.close();
      }
    });
  }

  async bindServers() {
    const families = new Set(this.config.publicHosts.map((host) => host.family));
    const binds = [];
    if (families.has('ipv6')) binds.push({ host: '::', ipv6Only: true });
    if (families.has('ipv4') || binds.length === 0) binds.push({ host: '0.0.0.0' });
    for (const bind of binds) {
      const server = net.createServer((socket) => this.handleClient(socket));
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen({ port: this.config.port, host: bind.host, ipv6Only: bind.ipv6Only }, resolve);
      });
      this.servers.push(server);
    }
  }

  handleClient(socket) {
    socket.setNoDelay(true);
    new ProxyConnection(socket, this.config, this.stats).run().catch((error) => {
      if (this.config.logConnections) {
        log(`closed ${socket.remoteAddress}:${socket.remotePort}: ${error.message}`);
      }
      socket.destroy();
    });
  }

  printStartupSummary() {
    console.log('========================================');
    console.log('Node.js MTProxy: running');
    console.log(`Public IPv4/IPv6: ${this.publicHostSummary()}`);
    console.log(`Port: ${this.config.port}`);
    const rawSecret = this.config.secret.toString('hex');
    console.log(`MTProxy Secret: ${rawSecret}`);
    if (DEFAULT_SECRETS.has(rawSecret)) {
      console.log('Warning: default example Secret is in use; this is not recommended');
      console.log(`Suggested random Secret: ${randomSecretHex()}`);
    }
    for (const publicHost of this.config.publicHosts) {
      for (const mode of enabledModes(this.config)) {
        const label = publicHost.family.toUpperCase();
        console.log(`TG ${label} link: tg://proxy?server=${publicHost.host}&port=${this.config.port}&secret=${publicSecret(this.config, mode)}`);
      }
    }
    console.log('========================================');
  }

  publicHostSummary() {
    const ipv4 = this.config.publicHosts.find((host) => host.family === 'ipv4')?.host || '';
    const ipv6 = this.config.publicHosts.find((host) => host.family === 'ipv6')?.host || '';
    if (ipv4 && ipv6) return `${ipv4} / ${ipv6}`;
    return ipv4 || ipv6 || 'unknown';
  }

  startStatsPrinter() {
    if (this.config.statsPrintPeriodMinutes <= 0) return;
    this.statsTimer = setInterval(
      () => this.stats.printSummary(),
      this.config.statsPrintPeriodMinutes * 60 * 1000
    );
  }

  close() {
    if (this.statsTimer) clearInterval(this.statsTimer);
    for (const server of this.servers) {
      server.close();
    }
    process.exit(0);
  }
}

class ProxyConnection {
  constructor(client, config, stats) {
    this.client = client;
    this.config = config;
    this.stats = stats;
  }

  async run() {
    const rawReader = new BufferedReader(this.client);
    let counted = false;
    try {
      const clientIo = await acceptFakeTls(rawReader, this.client, this.config);
      const handshake = await readHandshake(clientIo, this.config);
      const endpoints = endpointsForDc(handshake.backendDc, clientFamily(this.client));
      const backend = await connectTelegram(endpoints, this.config.connectTimeoutMillis, handshake.backendDc);
      this.stats.connectionOpened();
      counted = true;
      if (this.config.logConnections) {
        log(`accepted ${this.client.remoteAddress}:${this.client.remotePort}: dc=${handshake.backendDc} backend=${backend.endpoint.host}:${backend.endpoint.port}`);
      }
      await Promise.race([
        pipe(clientIo, backend.io, handshake.clientToProxyCipher, backend.clientToBackendCipher, this.stats, true, this.config.logConnections),
        pipe(backend.io, clientIo, backend.backendToClientCipher, handshake.proxyToClientCipher, this.stats, false, this.config.logConnections)
      ]);
      this.client.destroy();
      backend.socket.destroy();
    } catch (error) {
      if (this.config.logConnections) {
        log(`closed ${this.client.remoteAddress}:${this.client.remotePort}: ${error.message}`);
      }
      this.client.destroy();
    } finally {
      if (counted) this.stats.connectionClosed();
    }
  }
}

async function acceptFakeTls(reader, socket, config) {
  const first = await reader.readExactly(HANDSHAKE_SIZE);
  if (!isTlsClientHello(first)) {
    if (config.tls && !config.classic && !config.secure) {
      throw new Error('FakeTLS required but client did not send TLS ClientHello');
    }
    reader.prepend(first);
    return new PlainIo(reader, socket, false);
  }
  if (!config.tls) {
    throw new Error('FakeTLS client used but current mode is not tls');
  }
  const recordLength = first.readUInt16BE(3);
  const totalClientHelloLength = 5 + recordLength;
  if (totalClientHelloLength < HANDSHAKE_SIZE) {
    throw new Error('invalid FakeTLS ClientHello length');
  }
  const rest = await reader.readExactly(totalClientHelloLength - HANDSHAKE_SIZE);
  const clientHello = Buffer.concat([first, rest]);
  verifyClientHello(clientHello, config.secret);
  socket.write(buildServerHello(clientHello, config.secret));
  return new TlsIo(reader, socket);
}

function isTlsClientHello(data) {
  return data.length >= 11
    && data[0] === 0x16
    && data[1] === 0x03
    && data[5] === 0x01
    && data[9] === 0x03
    && data[10] === 0x03;
}

function verifyClientHello(clientHello, secret) {
  const digest = clientHello.subarray(11, 43);
  const zeroed = Buffer.from(clientHello);
  zeroed.fill(0, 11, 43);
  const computed = hmacSha256(secret, zeroed);
  for (let i = 0; i < 28; i += 1) {
    if (computed[i] !== digest[i]) throw new Error('invalid FakeTLS secret');
  }
  const timestamp = (computed.readUInt32LE(28) ^ digest.readUInt32LE(28)) >>> 0;
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(timestamp - now) > 600) {
    throw new Error('stale FakeTLS handshake');
  }
}

function buildServerHello(clientHello, secret) {
  const digest = clientHello.subarray(11, 43);
  const sessionIdLength = clientHello[43] || 0;
  const sessionId = 44 + sessionIdLength > clientHello.length
    ? Buffer.alloc(0)
    : clientHello.subarray(44, 44 + sessionIdLength);
  const certificateLength = 1024 + crypto.randomInt(3 * 1024);
  const certificateBytes = crypto.randomBytes(certificateLength);
  const firstPart = Buffer.from(TLS_SERVER_FIRST_PART);
  const secondPart = Buffer.from(TLS_SERVER_SECOND_PART);
  firstPart.writeUInt16BE(90 + sessionId.length, 3);
  firstPart.writeUInt32BE(86 + sessionId.length, 5);
  firstPart[5] = 2;
  firstPart[43] = sessionId.length;
  crypto.randomBytes(32).copy(secondPart, 13);
  secondPart.writeUInt16BE(certificateLength, 60);
  const digestPacket = Buffer.concat([digest, firstPart, sessionId, secondPart, certificateBytes]);
  const hmac = hmacSha256(secret, digestPacket);
  const mainPacket = Buffer.from(digestPacket.subarray(32));
  hmac.copy(mainPacket, 11);
  return mainPacket;
}

async function readHandshake(clientIo, config) {
  const init = await clientIo.readExactly(HANDSHAKE_SIZE);
  const clientToProxyCipher = clientCipher(false, init, config.secret);
  const decodedInit = clientToProxyCipher.update(init);
  const transport = transportFromDecodedInit(decodedInit, clientIo.fakeTls, config);
  if (!transport) throw new Error('unsupported transport or invalid secret');
  const dcId = decodedInit.readInt16LE(60);
  const plainInit = Buffer.from(init);
  decodedInit.copy(plainInit, 56, 56, 64);
  const proxyToClientCipher = clientCipher(true, reverseAll(plainInit), config.secret);
  return {
    dcId,
    backendDc: backendDc(dcId),
    transport,
    clientToProxyCipher,
    proxyToClientCipher
  };
}

function clientCipher(encrypt, init, secret) {
  const key = crypto.createHash('sha256')
    .update(init.subarray(8, 40))
    .update(secret)
    .digest();
  const iv = init.subarray(40, 56);
  return encrypt
    ? crypto.createCipheriv('aes-256-ctr', key, iv)
    : crypto.createDecipheriv('aes-256-ctr', key, iv);
}

function transportFromDecodedInit(decodedInit, fakeTls, config) {
  if (decodedInit.subarray(56, 60).equals(TRANSPORT_HEADER)) {
    if (fakeTls) return config.tls ? 'padded' : null;
    return config.secure ? 'padded' : null;
  }
  if (!fakeTls && config.classic && decodedInit.subarray(56, 60).equals(TAG_INTERMEDIATE)) return 'intermediate';
  if (!fakeTls && config.classic && decodedInit.subarray(56, 60).equals(TAG_ABRIDGED)) return 'abridged';
  return null;
}

function backendDc(dcId) {
  let dc = Math.abs(dcId);
  if (dc >= 10000) dc -= 10000;
  return dc;
}

async function connectTelegram(endpoints, timeoutMillis, dc) {
  let lastError = null;
  for (const endpoint of endpoints) {
    const socket = new net.Socket();
    try {
      await connectSocket(socket, endpoint.host, endpoint.port, timeoutMillis);
      const obfuscation = openBackendObfuscation(socket, dc);
      return {
        socket,
        endpoint,
        io: new PlainIo(new BufferedReader(socket), socket, false),
        clientToBackendCipher: obfuscation.clientToBackendCipher,
        backendToClientCipher: obfuscation.backendToClientCipher
      };
    } catch (error) {
      lastError = error;
      socket.destroy();
    }
  }
  throw new Error(`failed to connect Telegram DC: ${lastError ? lastError.message : 'no endpoint configured'}`);
}

function connectSocket(socket, host, port, timeoutMillis) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('connect timed out'));
    }, timeoutMillis);
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.connect(port, host, () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

function openBackendObfuscation(socket, dc) {
  const init = generateBackendInit(dc);
  const clientToBackendCipher = backendCipher(true, init);
  const encryptedInit = clientToBackendCipher.update(init);
  init.copy(encryptedInit, 8, 8, 56);
  const backendToClientCipher = backendCipher(false, reverseMiddle(init));
  socket.write(encryptedInit);
  return { clientToBackendCipher, backendToClientCipher };
}

function generateBackendInit(dc) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const init = crypto.randomBytes(HANDSHAKE_SIZE);
    if (isForbiddenInit(init)) continue;
    TRANSPORT_HEADER.copy(init, 56);
    init.writeInt16LE(dc || 2, 60);
    init[62] = 0;
    init[63] = 0;
    return init;
  }
  throw new Error('failed to generate Telegram backend obfuscation init');
}

function backendCipher(encrypt, init) {
  const key = init.subarray(8, 40);
  const iv = init.subarray(40, 56);
  return encrypt
    ? crypto.createCipheriv('aes-256-ctr', key, iv)
    : crypto.createDecipheriv('aes-256-ctr', key, iv);
}

function isForbiddenInit(init) {
  const first = init.readUInt32LE(0);
  return init[0] === 0xef
    || first === 0x44414548
    || first === 0x54534f50
    || first === 0x20544547
    || first === 0x4954504f
    || first === 0x02010316
    || first === 0xdddddddd
    || first === 0xeeeeeeee
    || (init[4] | init[5] | init[6] | init[7]) === 0;
}

async function pipe(fromIo, toIo, decrypt, encrypt, stats, fromClient, logConnections) {
  try {
    while (true) {
      let chunk = await fromIo.readAny();
      if (!chunk) break;
      if (fromClient) stats.recordFromClient(chunk.length);
      else stats.recordToClient(chunk.length);
      if (decrypt) chunk = decrypt.update(chunk);
      if (encrypt) chunk = encrypt.update(chunk);
      if (chunk.length > 0) await toIo.write(chunk);
    }
  } catch (error) {
    if (logConnections && !['Socket closed', 'Connection reset', 'Broken pipe'].includes(error.message)) {
      log(`pipe closed: ${error.message}`);
    }
  } finally {
    toIo.destroy();
    fromIo.destroy();
  }
}

class BufferedReader {
  constructor(socket) {
    this.socket = socket;
    this.buffers = [];
    this.length = 0;
    this.closed = false;
    this.error = null;
    this.waiters = [];
    socket.on('data', (chunk) => {
      this.buffers.push(chunk);
      this.length += chunk.length;
      this.resolveWaiters();
    });
    socket.on('end', () => this.close());
    socket.on('close', () => this.close());
    socket.on('error', (error) => {
      this.error = error;
      this.close();
    });
  }

  prepend(chunk) {
    this.buffers.unshift(chunk);
    this.length += chunk.length;
  }

  async readExactly(size) {
    while (this.length < size) await this.waitForData();
    return this.take(size);
  }

  async readAny(max = BUFFER_SIZE) {
    while (this.length === 0) {
      if (this.closed) return null;
      await this.waitForData();
    }
    return this.take(Math.min(max, this.length));
  }

  take(size) {
    const out = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const head = this.buffers[0];
      const copied = Math.min(head.length, size - offset);
      head.copy(out, offset, 0, copied);
      offset += copied;
      if (copied === head.length) {
        this.buffers.shift();
      } else {
        this.buffers[0] = head.subarray(copied);
      }
      this.length -= copied;
    }
    return out;
  }

  waitForData() {
    if (this.error) return Promise.reject(this.error);
    if (this.closed && this.length === 0) return Promise.reject(new Error('connection closed during read'));
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }

  resolveWaiters() {
    const waiters = this.waiters.splice(0);
    for (const waiter of waiters) waiter.resolve();
  }

  close() {
    this.closed = true;
    const waiters = this.waiters.splice(0);
    for (const waiter of waiters) {
      if (this.error) waiter.reject(this.error);
      else waiter.resolve();
    }
  }
}

class PlainIo {
  constructor(reader, socket, fakeTls) {
    this.reader = reader;
    this.socket = socket;
    this.fakeTls = fakeTls;
  }

  readExactly(size) {
    return this.reader.readExactly(size);
  }

  readAny() {
    return this.reader.readAny();
  }

  async write(chunk) {
    if (!this.socket.write(chunk)) await once(this.socket, 'drain');
  }

  destroy() {
    this.socket.destroy();
  }
}

class TlsIo extends PlainIo {
  constructor(reader, socket) {
    super(reader, socket, true);
    this.tlsBuffer = Buffer.alloc(0);
  }

  async readExactly(size) {
    while (this.tlsBuffer.length < size) {
      const payload = await this.readRecordPayload();
      this.tlsBuffer = Buffer.concat([this.tlsBuffer, payload]);
    }
    const out = this.tlsBuffer.subarray(0, size);
    this.tlsBuffer = this.tlsBuffer.subarray(size);
    return out;
  }

  async readAny(max = BUFFER_SIZE) {
    if (this.tlsBuffer.length === 0) {
      const payload = await this.readRecordPayload();
      if (!payload) return null;
      this.tlsBuffer = payload;
    }
    const copied = Math.min(max, this.tlsBuffer.length);
    const out = this.tlsBuffer.subarray(0, copied);
    this.tlsBuffer = this.tlsBuffer.subarray(copied);
    return out;
  }

  async readRecordPayload() {
    while (true) {
      const header = await this.reader.readExactly(5);
      const type = header[0];
      if (header[1] !== 0x03 || header[2] !== 0x03) throw new Error('invalid FakeTLS record version');
      const length = header.readUInt16BE(3);
      const payload = await this.reader.readExactly(length);
      if (type === 0x14) continue;
      if (type !== 0x17) throw new Error('invalid FakeTLS record type');
      return payload;
    }
  }

  async write(chunk) {
    let offset = 0;
    while (offset < chunk.length) {
      const part = chunk.subarray(offset, offset + TLS_MAX_CHUNK_SIZE);
      const header = Buffer.allocUnsafe(5);
      header[0] = 0x17;
      header[1] = 0x03;
      header[2] = 0x03;
      header.writeUInt16BE(part.length, 3);
      await super.write(Buffer.concat([header, part]));
      offset += part.length;
    }
  }
}

class ProxyStats {
  constructor() {
    this.connects = 0n;
    this.currentConnects = 0n;
    this.octetsFromClient = 0n;
    this.octetsToClient = 0n;
    this.msgsFromClient = 0n;
    this.msgsToClient = 0n;
  }

  connectionOpened() {
    this.connects += 1n;
    this.currentConnects += 1n;
  }

  connectionClosed() {
    if (this.currentConnects > 0n) this.currentConnects -= 1n;
  }

  recordFromClient(bytes) {
    this.octetsFromClient += BigInt(bytes);
    this.msgsFromClient += 1n;
  }

  recordToClient(bytes) {
    this.octetsToClient += BigInt(bytes);
    this.msgsToClient += 1n;
  }

  printSummary() {
    const octets = this.octetsFromClient + this.octetsToClient;
    const msgs = this.msgsFromClient + this.msgsToClient;
    console.log(`${new Date().toISOString()} Stats: ${this.connects} connects (${this.currentConnects} current), ${(Number(octets) / 1_000_000).toFixed(2)} MB, ${msgs} msgs`);
  }
}

function endpointsForDc(dc, family) {
  const primary = family === 'ipv6' ? DC_V6 : DC_V4;
  const fallback = family === 'ipv6' ? DC_V4 : DC_V6;
  return [...(primary.get(dc) || []), ...(fallback.get(dc) || [])];
}

function clientFamily(socket) {
  return socket.remoteFamily === 'IPv6' && !socket.remoteAddress?.startsWith('::ffff:') ? 'ipv6' : 'ipv4';
}

function enabledModes(config) {
  const modes = [];
  if (config.classic) modes.push('classic');
  if (config.secure) modes.push('secure');
  if (config.tls) modes.push('tls');
  return modes;
}

function publicSecret(config, mode) {
  const raw = config.secret.toString('hex');
  if (mode === 'classic') return raw;
  if (mode === 'secure') return `dd${raw}`;
  return `ee${raw}${Buffer.from(config.tlsDomain, 'utf8').toString('hex')}`;
}

function randomSecretHex() {
  return crypto.randomBytes(16).toString('hex');
}

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function reverseAll(input) {
  return Buffer.from(input).reverse();
}

function reverseMiddle(input) {
  const out = Buffer.from(input);
  for (let i = 8, j = 55; i < j; i += 1, j -= 1) {
    const tmp = out[i];
    out[i] = out[j];
    out[j] = tmp;
  }
  return out;
}

function isIpv4(value) {
  return /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(value);
}

function isIpv6(value) {
  return value.includes(':') && /^[0-9A-Fa-f:.]+$/.test(value);
}

function log(message) {
  console.log(`${new Date().toISOString()} ${message}`);
}

function printHelp() {
  console.log(`Node.js MTProxy minimal server

Options:
  --generate-secret
  --config <path>
  --secret <hex>
  --classic <true|false>
  --secure <true|false>
  --tls <true|false>
  --port <port>
  --tls-domain <domain>
  --connect-timeout <ms>
  --log-connections <true|false>
  --stats-print-period-minutes <minutes>`);
}

main();
