const http = require('http');

const port = process.env.PORT || 3000;
http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('ok');
}).listen(port, '0.0.0.0', () => {
  console.log('[health] listening on ' + port);
});

require('./node-app/index.js');
