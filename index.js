const http = require('http');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');
const { spawn } = require('child_process');

const UUID_RAW = (process.env.UUID || '').toLowerCase();
const UUID = UUID_RAW.replace(/-/g, '');
const HOST = process.env.NODE_HOST || 'lytestkbab.infrlo.com';
const PORT = process.env.PORT || 5000;
const WS_PATH = '/' + UUID_RAW + '-vless';
const LOG = path.join(__dirname, 'app.log');
const CA_PATH = path.join(__dirname, 'ca.pem');
const CF_BIN = path.join(__dirname, 'cloudflared');
let ARGO_DOMAIN = '';
let cfProc = null;

function log(msg) {
  const line = new Date().toISOString() + ' ' + msg + '\n';
  try { fs.appendFileSync(LOG, line); } catch (e) {}
  process.stdout.write(line);
}

function wsFrame(data, opcode = 0x2) {
  const len = data.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  header[0] = 0x80 | opcode;
  return Buffer.concat([header, data]);
}

class WSConn {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.fragOpcode = 0;
    this.fragBuffer = null;
    this.closed = false;
    this.onMessage = null;
    this.onClose = null;
    socket.on('data', (d) => this.feed(d));
    socket.on('close', () => this.handleClose());
    socket.on('error', () => this.handleClose());
    socket.on('drain', () => { if (this.onDrain) this.onDrain(); });
  }
  feed(data) {
    this.buffer = Buffer.concat([this.buffer, data]);
    while (true) {
      if (this.buffer.length < 2) return;
      const b0 = this.buffer[0];
      const b1 = this.buffer[1];
      const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) {
        if (this.buffer.length < 4) return;
        len = this.buffer.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (this.buffer.length < 10) return;
        len = Number(this.buffer.readBigUInt64BE(2));
        off = 10;
      }
      let mask = null;
      if (masked) {
        if (this.buffer.length < off + 4) return;
        mask = this.buffer.slice(off, off + 4);
        off += 4;
      }
      if (this.buffer.length < off + len) return;
      let payload = this.buffer.slice(off, off + len);
      if (mask) {
        payload = Buffer.from(payload);
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
      }
      this.buffer = this.buffer.slice(off + len);

      if (opcode === 0x8) { this.close(); return; }
      if (opcode === 0x9) { this.sendFrame(payload, 0xA); continue; }
      if (opcode === 0xA) continue;

      if (opcode === 0x0) {
        if (!this.fragBuffer) continue;
        this.fragBuffer = Buffer.concat([this.fragBuffer, payload]);
        if (fin) {
          const full = this.fragBuffer;
          this.fragBuffer = null;
          if (this.onMessage) this.onMessage(full, this.fragOpcode);
        }
      } else if (opcode === 0x1 || opcode === 0x2) {
        if (!fin) {
          this.fragOpcode = opcode;
          this.fragBuffer = payload;
        } else if (this.onMessage) {
          this.onMessage(payload, opcode);
        }
      }
    }
  }
  sendFrame(data, opcode = 0x2) {
    if (this.closed) return true;
    try { return this.socket.write(wsFrame(data, opcode)); } catch (e) { return true; }
  }
  send(data) { return this.sendFrame(data, 0x2); }
  close() {
    if (this.closed) return;
    this.closed = true;
    try { this.socket.write(wsFrame(Buffer.alloc(0), 0x8)); } catch (e) {}
    try { this.socket.end(); } catch (e) {}
    this.handleClose();
  }
  handleClose() {
    if (this.closed && this.notified) return;
    this.closed = true;
    this.notified = true;
    if (this.onClose) this.onClose();
  }
}

function parseVless(buf) {
  if (buf.length < 18) return null;
  if (buf[0] !== 0) return { error: 'bad version' };
  const id = buf.slice(1, 17).toString('hex');
  if (id !== UUID) return { error: 'bad uuid' };
  const addonLen = buf[17];
  const base = 18 + addonLen;
  if (buf.length < base + 4) return null;
  const cmd = buf[base];
  const port = buf.readUInt16BE(base + 1);
  const atyp = buf[base + 3];
  let off = base + 4;
  let addr;
  if (atyp === 1) {
    if (buf.length < off + 4) return null;
    addr = [...buf.slice(off, off + 4)].join('.');
    off += 4;
  } else if (atyp === 2) {
    if (buf.length < off + 1) return null;
    const l = buf[off];
    off += 1;
    if (buf.length < off + l) return null;
    addr = buf.slice(off, off + l).toString('utf8');
    off += l;
  } else if (atyp === 3) {
    if (buf.length < off + 16) return null;
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(off + i).toString(16));
    addr = parts.join(':');
    off += 16;
  } else {
    return { error: 'bad atyp' };
  }
  return { cmd, port, addr, rest: buf.slice(off) };
}

function handleUpgrade(req, socket, head) {
  const reqPath = (req.url || '').split('?')[0];
  let decoded = reqPath;
  try { decoded = decodeURIComponent(reqPath); } catch (e) {}
  if (decoded !== WS_PATH) {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    socket.destroy();
    return;
  }
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  const accept = crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n'
  );
  log('[ws] client connected from ' + (socket.remoteAddress || '?'));
  socket.setNoDelay(true);
  const ws = new WSConn(socket);
  if (head && head.length) ws.feed(head);
  let target = null;
  let headerBuf = Buffer.alloc(0);
  let parsed = false;

  ws.onMessage = (payload) => {
    if (!parsed) {
      headerBuf = Buffer.concat([headerBuf, payload]);
      const info = parseVless(headerBuf);
      if (!info) return;
      if (info.error) {
        log('[vless] rejected: ' + info.error);
        ws.close();
        return;
      }
      parsed = true;
      log('[vless] target ' + info.addr + ':' + info.port + ' cmd=' + info.cmd);
      if (info.cmd !== 1) {
        log('[vless] unsupported cmd ' + info.cmd);
        ws.close();
        return;
      }
      target = net.connect({ host: info.addr, port: info.port });
      target.setNoDelay(true);
      target.on('connect', () => {
        ws.send(Buffer.from([0, 0]));
        if (info.rest && info.rest.length) target.write(info.rest);
      });
      target.on('data', (d) => { if (!ws.send(d)) target.pause(); });
      target.on('error', (e) => { log('[tcp] ' + e.message); ws.close(); });
      target.on('close', () => ws.close());
    } else if (target) {
      target.write(payload);
    }
  };
  ws.onDrain = () => { if (target) target.resume(); };
  ws.onClose = () => {
    if (target) target.destroy();
  };
}

function downloadFile(url, dest, cb) {
  const mod = url.startsWith('https:') ? https : http;
  mod.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (res) => {
    if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
      res.resume();
      return downloadFile(res.headers.location, dest, cb);
    }
    if (res.statusCode !== 200) {
      res.resume();
      return cb(new Error('HTTP ' + res.statusCode));
    }
    const f = fs.createWriteStream(dest);
    res.pipe(f);
    f.on('finish', () => f.close(() => cb(null)));
  }).on('error', cb);
}

function startCloudflared() {
  const begin = () => {
    try { fs.writeFileSync(CA_PATH, require('tls').rootCertificates.join('\n')); } catch (e) {}
    const args = ['tunnel', '--no-autoupdate', '--url', 'http://127.0.0.1:' + PORT, '--protocol', 'http2'];
    log('[cloudflared] starting: ' + args.join(' '));
    cfProc = spawn(CF_BIN, args, {
      env: Object.assign({}, process.env, { SSL_CERT_FILE: CA_PATH, SSL_CERT_DIR: __dirname }),
      stdio: ['ignore', 'pipe', 'pipe']
    });
    const onData = (d) => {
      for (const line of d.toString().split('\n')) {
        const t = line.trim();
        if (!t) continue;
        log('[cloudflared] ' + t);
        const m = t.match(/https:\/\/((?!api\.)[a-z0-9-]+\.trycloudflare\.com)/i);
        if (m) {
          ARGO_DOMAIN = m[1];
          log('[argo] tunnel ready: ' + ARGO_DOMAIN);
          try { fs.writeFileSync(path.join(__dirname, 'argo.txt'), ARGO_DOMAIN + '\n'); } catch (e) {}
        }
      }
    };
    cfProc.stdout.on('data', onData);
    cfProc.stderr.on('data', onData);
    cfProc.on('exit', (code) => {
      log('[cloudflared] exited code ' + code + ', restarting in 5s');
      cfProc = null;
      setTimeout(startCloudflared, 5000);
    });
  };
  if (fs.existsSync(CF_BIN)) {
    try { fs.chmodSync(CF_BIN, 0o755); } catch (e) {}
    return begin();
  }
  const arch = ['arm64', 'aarch64', 'arm'].includes(os.arch()) ? 'arm64' : 'amd64';
  const url = 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-' + arch;
  log('[cloudflared] downloading ' + url);
  downloadFile(url, CF_BIN + '.tmp', (err) => {
    if (err) { log('[cloudflared] download failed: ' + err.message); return setTimeout(startCloudflared, 10000); }
    try { fs.renameSync(CF_BIN + '.tmp', CF_BIN); fs.chmodSync(CF_BIN, 0o755); } catch (e) { log('[cloudflared] install failed: ' + e.message); return setTimeout(startCloudflared, 10000); }
    log('[cloudflared] downloaded ' + fs.statSync(CF_BIN).size + ' bytes');
    begin();
  });
}

const server = http.createServer((req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.url === '/sub') {
    const direct = 'vless://' + UUID_RAW + '@' + HOST + ':443?encryption=none&security=tls&type=ws&host=' + HOST + '&path=' + encodeURIComponent(WS_PATH) + '&sni=' + HOST + '&fp=chrome#Infrlo-Direct';
    let out = direct + '\n';
    if (ARGO_DOMAIN) {
      const cfip = process.env.CFIP || 'www.visa.co.jp';
      out += 'vless://' + UUID_RAW + '@' + cfip + ':443?encryption=none&security=tls&type=ws&host=' + ARGO_DOMAIN + '&path=' + encodeURIComponent(WS_PATH) + '&sni=' + ARGO_DOMAIN + '&fp=chrome#Infrlo-Argo' + '\n';
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(out);
    return;
  }
  if (req.url === '/argo') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(ARGO_DOMAIN ? ARGO_DOMAIN + '\n' : 'not ready\n');
    return;
  }
  if (req.url && req.url.startsWith('/speed')) {
    const mb = Math.min(20, Math.max(1, parseInt((req.url.split('mb=')[1] || '5'), 10) || 5));
    const buf = Buffer.alloc(mb * 1024 * 1024, 0x41);
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': buf.length });
    res.end(buf);
    return;
  }
  if (req.url === '/log') {
    try { res.end(fs.readFileSync(LOG, 'utf8').slice(-200000)); }
    catch (e) { res.end('no log'); }
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('ok');
});

function UUIDWithDashes() {
  return UUID.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
}

server.on('upgrade', handleUpgrade);
server.listen(PORT, '0.0.0.0', () => {
  log('[health] listening on ' + PORT + ' path ' + WS_PATH);
  startCloudflared();
});
