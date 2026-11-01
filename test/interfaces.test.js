import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig, saveConfig } from '../src/config.js';
import { startGui } from '../src/gui/server.js';
const cli = new URL('../bin/purgelog.js', import.meta.url).pathname;
test('CLI redacts stdin and keeps summary off stdout', () => {
  const result = spawnSync(process.execPath, [cli, '--summary'], { input: 'password=secret', encoding: 'utf8' });
  assert.equal(result.status, 0); assert.equal(result.stdout, 'password=<PASSWORDS_1>');
  assert.equal(JSON.parse(result.stderr).total, 1); assert(!result.stderr.includes('secret'));
});
test('CLI refuses existing output files and preserves input', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'purgelog-'));
  try {
    const input = join(dir, 'raw.log'), out = join(dir, 'clean.log');
    await writeFile(input, 'password=secret');
    execFileSync(process.execPath, [cli, input, '-o', out]);
    assert.equal(await readFile(input, 'utf8'), 'password=secret');
    assert.equal(await readFile(out, 'utf8'), 'password=<PASSWORDS_1>');
    assert.equal(spawnSync(process.execPath, [cli, input, '-o', out]).status, 1);
    assert.equal(spawnSync(process.execPath, [cli, input, '-o', input]).status, 1);
  } finally { await rm(dir, { recursive: true }); }
});
test('bad credential file fails closed without printing its contents', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'purgelog-'));
  try {
    const file = join(dir, 'private.json'); await writeFile(file, '{SECRET-CONTENT');
    const result = spawnSync(process.execPath, [cli, '--secrets', file], { input: 'unchanged-sensitive-input', encoding: 'utf8' });
    assert.equal(result.status, 1); assert.equal(result.stdout, ''); assert(!result.stderr.includes('SECRET-CONTENT'));
  } finally { await rm(dir, { recursive: true }); }
});
test('config and private credentials are composed, settings export excludes secrets', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'purgelog-'));
  try {
    const config = join(dir, 'settings.json'), secrets = join(dir, 'private.json');
    await writeFile(config, '{"categories":{"emails":{"enabled":false}}}');
    await writeFile(secrets, '{"version":1,"credentials":[{"name":"demo","value":"private-demo"}]}');
    const result = await loadConfig(config, secrets); assert.equal(result.credentials.length, 1); assert.equal(result.categories.emails.enabled, false);
    await assert.rejects(saveConfig(join(dir, 'export.json'), result));
  } finally { await rm(dir, { recursive: true }); }
});
test('settings requires a terminal instead of hanging in pipelines', () => {
  const result = spawnSync(process.execPath, [cli, 'settings'], { encoding: 'utf8' });
  assert.equal(result.status, 1); assert.match(result.stderr, /interactive terminal/);
});
test('GUI serves only bundled assets on tokenized loopback paths', async () => {
  const session = await startGui();
  try {
    const page = await fetch(session.url); assert.equal(page.status, 200); assert.match(await page.text(), /Original log/);
    assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.equal(page.headers.get('cache-control'), 'no-store');
    assert.equal((await fetch(new URL('/config.json', session.url))).status, 404);
    assert.equal((await fetch(session.url, { method: 'POST', body: 'secret' })).status, 403);
    assert.equal((await fetch(session.url, { headers: { Origin: 'https://evil.example' } })).status, 403);
    assert.equal((await fetch(session.url + 'core.js')).status, 200);
    assert.equal((await fetch(session.url + 'config.json')).status, 200);
  } finally { session.close(); }
});
