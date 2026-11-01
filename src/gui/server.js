import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { normalizeConfig } from '../core/index.js';

export async function startGui(input = {}) {
  const config = normalizeConfig(input);
  const token = randomBytes(24).toString('hex');
  const routes = new Map([
    ['', ['text/html; charset=utf-8', new URL('./index.html', import.meta.url)]],
    ['app.js', ['text/javascript; charset=utf-8', new URL('./app.js', import.meta.url)]],
    ['style.css', ['text/css; charset=utf-8', new URL('./style.css', import.meta.url)]],
    ['core.js', ['text/javascript; charset=utf-8', new URL('../core/index.js', import.meta.url)]],
  ]);
  const assets = new Map(await Promise.all([...routes].map(async ([name, [type, path]]) => [name, { type, body: await readFile(path) }])));
  const server = createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    if (req.method !== 'GET' || req.headers.host !== `127.0.0.1:${server.address().port}` || req.headers.origin && req.headers.origin !== `http://${req.headers.host}` || req.headers['sec-fetch-site'] === 'cross-site') { res.writeHead(403); res.end(); return; }
    const prefix = `/${token}/`;
    if (!req.url.startsWith(prefix)) { res.writeHead(404); res.end(); return; }
    const name = req.url.slice(prefix.length);
    if (name === 'config.json') { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(config)); return; }
    const asset = assets.get(name);
    if (!asset) { res.writeHead(404); res.end(); return; }
    res.setHeader('Content-Type', asset.type); res.end(asset.body);
  });
  await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); });
  return { url: `http://127.0.0.1:${server.address().port}/${token}/`, close() { server.closeAllConnections(); server.close(); } };
}
