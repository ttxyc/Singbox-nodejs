const http = require('http');
const fs = require('fs');
const path = require('path');

const LOG = path.join(__dirname, 'app.log');
const origWrite = process.stdout.write.bind(process.stdout);
process.stdout.write = (chunk, ...args) => {
  try {
    fs.appendFileSync(LOG, typeof chunk === 'string' ? chunk : Buffer.from(chunk));
  } catch (e) {}
  return origWrite(chunk, ...args);
};

const port = process.env.PORT || 5000;
http.createServer((req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.url === '/sub') {
    try { res.end(fs.readFileSync(path.join(__dirname, 'sub.txt'))); }
    catch (e) { res.statusCode = 404; res.end('not ready'); }
    return;
  }
  if (req.url === '/log') {
    try { res.end(fs.readFileSync(LOG, 'utf8').slice(-200000)); }
    catch (e) { res.end('no log'); }
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('ok');
}).listen(port, '0.0.0.0', () => {
  console.log('[health] listening on ' + port);
});

require('./node-app/index.js');
