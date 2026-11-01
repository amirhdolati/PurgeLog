import { readFile, writeFile } from 'node:fs/promises';
import { normalizeConfig } from './core/index.js';

export async function readConfigFile(path) {
  let raw;
  try { raw = await readFile(path, 'utf8'); } catch { throw new Error('Could not read the configuration file.'); }
  try { return normalizeConfig(JSON.parse(raw)); } catch { throw new Error('Invalid configuration file. Check the documented schema; no values have been printed.'); }
}
export async function loadConfig(configPath, secretsPath) {
  const config = configPath ? await readConfigFile(configPath) : normalizeConfig();
  if (!secretsPath) return config;
  let secrets;
  try {
    secrets = JSON.parse(await readFile(secretsPath, 'utf8'));
    if (!secrets || typeof secrets !== 'object' || Array.isArray(secrets) || Object.keys(secrets).some(k => !['version', 'credentials'].includes(k)) || !Array.isArray(secrets.credentials)) throw new Error();
    return normalizeConfig({ ...config, credentials: [...config.credentials, ...normalizeConfig(secrets).credentials] });
  } catch { throw new Error('Invalid or unreadable credentials file. Expected version 1 and a credentials array.'); }
}
export async function saveConfig(path, config, { overwrite = false } = {}) {
  const normalized = normalizeConfig(config);
  if (normalized.credentials.length) throw new Error('Settings cannot save credential values. Keep them in a separate private file.');
  const { credentials, ...publicConfig } = normalized;
  if (overwrite) {
    const { lstat, rename, unlink } = await import('node:fs/promises');
    const { randomBytes } = await import('node:crypto');
    if (!(await lstat(path)).isFile()) throw new Error('Settings destination must be a regular file.');
    const temporary = `${path}.${randomBytes(8).toString('hex')}.tmp`;
    try {
      await writeFile(temporary, JSON.stringify(publicConfig, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      await rename(temporary, path);
    } finally { await unlink(temporary).catch(() => {}); }
  } else await writeFile(path, JSON.stringify(publicConfig, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
