const http = require('http');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const UUID_RAW = (process.env.UUID || '').toLowerCase();
const UUID = UUID_RAW.replace(/-/g, '');
const HOST = process.env.NODE_HOST || 'lytestkbab.infrlo.com';
const PORT = process.env.PORT || 5000;
const WS_PATH = '/' + UUID_RAW + '-vless';
const LOG = path.join(__dirname, 'app.log');

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
    if (this.closed) return;
    try { this.socket.write(wsFrame(data, opcode)); } catch (e) {}
  }
  send(data) { this.sendFrame(data, 0x2); }
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
      target.on('data', (d) => ws.send(d));
      target.on('error', (e) => { log('[tcp] ' + e.message); ws.close(); });
      target.on('close', () => ws.close());
    } else if (target) {
      target.write(payload);
    }
  };
  ws.onClose = () => {
    if (target) target.destroy();
  };
}

const server = http.createServer((req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.url === '/sub') {
    const link = 'vless://' + UUID_RAW + '@' + HOST + ':443?encryption=none&security=tls&type=ws&host=' + HOST + '&path=' + encodeURIComponent(WS_PATH) + '&sni=' + HOST + '&fp=chrome#Infrlo-WS';
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(link + '\n');
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
server.listen(PORT, '0.0.0.0', () => log('[health] listening on ' + PORT + ' path ' + WS_PATH));
