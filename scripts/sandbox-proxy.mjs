// Allowlist forward proxy. The sandbox is the only client. CONNECT is HTTPS only.
import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns/promises';
import { pathToFileURL } from 'node:url';
import { hostAllowed, ipAllowed } from './sandbox-lib.mjs';

function deny(socket) {
  socket.write('HTTP/1.1 403 denied\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  socket.destroy();
}

async function publicAddress(host) {
  if (!hostAllowed(host)) return null;
  let addrs = [];
  try { addrs = await dns.lookup(host, { all: true }); } catch { return null; }
  return addrs.find((a) => ipAllowed(a.address))?.address || null;
}

export function createProxy() {
  const server = http.createServer((req, res) => {
    res.writeHead(403);
    res.end('denied');
  });
  server.on('connect', (req, socket) => {
    const idx = String(req.url || '').lastIndexOf(':');
    const host = idx > 0 ? req.url.slice(0, idx) : '';
    const port = idx > 0 ? Number(req.url.slice(idx + 1)) : 0;
    if (port !== 443) { deny(socket); return; }
    publicAddress(host).then((address) => {
      if (!address) { deny(socket); return; }
      const upstream = net.connect(443, address, () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        upstream.pipe(socket);
        socket.pipe(upstream);
      });
      upstream.on('error', () => deny(socket));
    }).catch(() => deny(socket));
    socket.on('error', () => {});
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = createProxy();
  server.listen(Number(process.env.PORT || 3128), '0.0.0.0', () => {
    console.log(`proxy listening ${server.address().port}`);
  });
}
