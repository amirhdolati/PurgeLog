#!/usr/bin/env node
import { readFile, writeFile, realpath, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { sanitize } from '../src/core/index.js';
import { loadConfig } from '../src/config.js';

const HELP = `PurgeLog — Redact secrets. Keep the context.

Usage:
  purgelog [input.log] [-o cleaned.log] [options]
  cat input.log | purgelog [options]
  purgelog settings [--config new-settings.json]
  purgelog gui [--config settings.json] [--secrets private.json] [--no-open]

Options:
  -o, --output FILE    Create a new file (never overwrite an existing file)
  -c, --config FILE    Load JSON settings
  -s, --secrets FILE   Load exact custom credential values from private JSON
      --action MODE    label, mask, remove, or replace
      --replacement TEXT  Text for the replace action
      --summary        Write category counts to stderr, never original values
      --no-open        Print local GUI URL without opening a browser
  -h, --help           Show this help
      --version        Print the version

Runtime is offline. Detection is best effort; review output before sharing.
`;

async function main() {
  let parsed;
  try {
    parsed = parseArgs({ allowPositionals: true, options: {
      output: { type: 'string', short: 'o' }, config: { type: 'string', short: 'c' },
      secrets: { type: 'string', short: 's' }, action: { type: 'string' }, replacement: { type: 'string' },
      summary: { type: 'boolean' }, 'no-open': { type: 'boolean' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean' },
    } });
  } catch { throw new Error('Invalid arguments. Run purgelog --help.'); }
  const { values: flags, positionals } = parsed;
  if (flags.help) { process.stdout.write(HELP); return; }
  if (flags.version) { process.stdout.write('0.1.0\n'); return; }
  if (positionals.length > 1) throw new Error('Expected at most one input file or command.');
  const command = positionals[0];
  if (command === 'settings') {
    const { runSettings } = await import('../src/tui.js');
    await runSettings(flags.config); return;
  }
  const config = await loadConfig(flags.config, flags.secrets);
  if (flags.action !== undefined) config.action = flags.action;
  if (flags.replacement !== undefined) config.replacement = flags.replacement;
  if (command === 'gui') {
    const { startGui } = await import('../src/gui/server.js');
    const session = await startGui(config);
    process.stderr.write(`PurgeLog is available at ${session.url}\nProcessing stays in your browser. Press Ctrl+C to close.\n`);
    if (!flags['no-open']) {
      const { execFile } = await import('node:child_process');
      const platform = process.platform;
      if (platform === 'darwin') execFile('open', [session.url], () => {});
      else if (platform === 'win32') execFile('rundll32', ['url.dll,FileProtocolHandler', session.url], () => {});
      else execFile('xdg-open', [session.url], () => {});
    }
    const close = () => { session.close(); };
    process.once('SIGINT', close); process.once('SIGTERM', close);
    return;
  }
  if (!command && process.stdin.isTTY) { process.stdout.write(HELP); return; }
  if (flags.output && command) {
    if (resolve(flags.output) === resolve(command)) throw new Error('Input and output must be different files.');
    try { if (await realpath(flags.output) === await realpath(command)) throw new Error('Input and output must be different files.'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  let input;
  if (command && command !== '-') {
    if ((await stat(command)).size > 10 * 1024 * 1024) throw new Error('Input exceeds the 10 MiB file limit.');
    input = await readFile(command, 'utf8');
  } else {
    const chunks = []; let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > 10 * 1024 * 1024) throw new Error('Input exceeds the 10 MiB file limit.');
      chunks.push(chunk);
    }
    input = Buffer.concat(chunks).toString('utf8');
  }
  const result = sanitize(input, config);
  if (flags.output) await writeFile(flags.output, result.text, { flag: 'wx', mode: 0o600 });
  else process.stdout.write(result.text);
  if (flags.summary) process.stderr.write(JSON.stringify({ total: result.total, categories: result.summary }) + '\n');
}
process.stdout.on('error', error => { if (error.code === 'EPIPE') process.exit(0); });
main().catch(error => {
  const safe = error.code ? 'File operation failed. Check paths, permissions, and whether the output already exists.' : error.message;
  process.stderr.write(`PurgeLog: ${safe}\n`); process.exitCode = 1;
});
