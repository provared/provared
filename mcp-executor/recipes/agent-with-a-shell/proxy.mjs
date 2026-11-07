// proxy.mjs: runs in the guard container. A TLS-terminating proxy, 0.0.0.0:8443 (TLS) to 127.0.0.1:8796 (plain, the guard). Stands for "something else encrypts"; not hardened, no client authentication.
import tls from 'node:tls';
import net from 'node:net';
import { readFileSync } from 'node:fs';
const srv = tls.createServer({ key: readFileSync('/data/tls/key.pem'), cert: readFileSync('/data/tls/cert.pem'), minVersion: 'TLSv1.2' }, (s) => {
  const u = net.connect(8796, '127.0.0.1');
  s.pipe(u); u.pipe(s);
  const end = () => { s.destroy(); u.destroy(); };
  s.on('error', end); u.on('error', end); s.on('close', end); u.on('close', end);
});
srv.on('tlsClientError', (e) => console.log('tlsClientError', e.code || e.message));
srv.listen(8443, '0.0.0.0', () => console.log('proxy listening 8443'));
