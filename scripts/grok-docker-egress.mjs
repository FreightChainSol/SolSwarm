import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns/promises';
import { pathToFileURL } from 'node:url';

const HOSTS = new Set(['cli-chat-proxy.grok.com', 'auth.x.ai']);
export function allowedGrokDestination(authority) {
  return typeof authority === 'string' && /^[a-z.-]+:443$/.test(authority) && HOSTS.has(authority.slice(0, -4));
}
export function publicV4(ip) {
  if (!net.isIPv4(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  return a !== 0 && a !== 10 && a !== 127 && a < 224
    && !(a === 100 && b >= 64 && b <= 127) && !(a === 169 && b === 254)
    && !(a === 172 && b >= 16 && b <= 31) && !(a === 192 && [0, 168].includes(b))
    && !(a === 198 && [18, 19].includes(b));
}
export function createGrokProxy() {
  const server = http.createServer({ maxHeaderSize: 8192 }, (_, response) => { response.writeHead(403); response.end(); });
  server.maxConnections = 32;
  server.headersTimeout = 5000;
  server.on('connect', async (request, socket, head) => {
    socket.on('error', () => {});
    socket.setTimeout(70_000, () => socket.destroy());
    if (!allowedGrokDestination(request.url) || head.length) { socket.destroy(); return; }
    let upstream;
    socket.once('close', () => upstream?.destroy());
    try {
      const addresses = await dns.lookup(request.url.slice(0, -4), { all: true, family: 4 });
      const address = addresses.find((entry) => publicV4(entry.address))?.address;
      if (!address || socket.destroyed) { socket.destroy(); return; }
      upstream = net.connect({ host: address, port: 443 });
      upstream.setTimeout(70_000, () => upstream.destroy());
      upstream.on('error', () => socket.destroy());
      upstream.once('close', () => socket.destroy());
      upstream.once('connect', () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        upstream.pipe(socket);
        socket.pipe(upstream);
      });
    } catch { socket.destroy(); }
  });
  return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) createGrokProxy().listen(3128, '0.0.0.0');
