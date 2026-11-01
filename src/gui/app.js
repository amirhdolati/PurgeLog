import { CATEGORY_NAMES, normalizeConfig, sanitize } from './core.js';
const $ = id => document.getElementById(id);
const names = { tokens: 'Tokens & authorization', passwords: 'Passwords & private keys', cookies: 'Cookies', emails: 'Email addresses', phones: 'Phone numbers (broad)', ipAddresses: 'IPv4 addresses', userPaths: 'Personal folder paths', custom: 'Custom keys & credentials' };
let config = normalizeConfig();
let result = null;
let fileError = false;
function status(message) { $('status').textContent = message; }
function invalidate() {
  result = null; $('output').value = ''; $('copy').disabled = true; $('download').disabled = true;
  $('result-state').textContent = 'Run redaction'; $('summary').textContent = 'Input or settings changed. Run redaction to generate fresh output.';
}
function renderSettings() {
  $('categories').replaceChildren();
  for (const name of CATEGORY_NAMES) {
    const label = document.createElement('label'); label.className = 'category';
    const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.checked = config.categories[name].enabled;
    checkbox.addEventListener('change', () => { config.categories[name].enabled = checkbox.checked; invalidate(); });
    label.append(checkbox, document.createTextNode(names[name])); $('categories').append(label);
  }
  $('action').value = config.action; $('replacement').value = config.replacement;
  $('replacement-field').hidden = config.action !== 'replace';
  $('credential-status').textContent = `${config.credentials.length} custom credential(s) loaded in memory.`;
}
async function readSelectedFile(input, limit = 1024 * 1024) {
  const file = input.files[0];
  if (!file) return null;
  if (file.size > limit) throw new Error('Selected file is too large.');
  return file.text();
}
function download(text, filename) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('input').addEventListener('input', () => { $('input-count').textContent = `${$('input').value.length.toLocaleString()} characters`; invalidate(); });
$('action').addEventListener('change', () => { config.action = $('action').value; $('replacement-field').hidden = config.action !== 'replace'; invalidate(); });
$('replacement').addEventListener('input', () => { config.replacement = $('replacement').value; invalidate(); });
$('sanitize').addEventListener('click', () => {
  try {
    result = sanitize($('input').value, config); $('output').value = result.text;
    $('copy').disabled = false; $('download').disabled = false;
    $('result-state').textContent = `${result.total} redaction(s)`;
    $('summary').textContent = Object.entries(result.summary).map(([name, count]) => `${names[name]}: ${count}`).join(' · ') || 'No supported patterns found. This does not prove the input is safe.';
    status('Review the output before sharing.');
  } catch { invalidate(); status('Could not process input. Check settings and the 10 MiB input limit.'); }
});
$('copy').addEventListener('click', async () => { if (!result) return; try { await navigator.clipboard.writeText(result.text); status('Sanitized output copied.'); } catch { status('Clipboard unavailable. Select and copy the output manually.'); } });
$('download').addEventListener('click', () => { if (result) download(result.text, 'sanitized.log'); });
$('export-settings').addEventListener('click', () => { const { credentials, ...publicConfig } = config; download(JSON.stringify(publicConfig, null, 2) + '\n', 'purgelog.json'); status('Settings exported. Credential values were excluded.'); });
for (const id of ['config-file', 'secrets-file']) $(id).addEventListener('change', async () => {
  invalidate(); $('sanitize').disabled = true;
  try {
    const raw = await readSelectedFile($(id)); if (raw === null) return;
    const parsed = JSON.parse(raw);
    if (id === 'secrets-file') {
      if (!parsed || !Array.isArray(parsed.credentials) || Object.keys(parsed).some(k => !['version', 'credentials'].includes(k))) throw new Error();
      config = normalizeConfig({ ...config, credentials: normalizeConfig(parsed).credentials });
    } else {
      const loaded = normalizeConfig(parsed);
      config = normalizeConfig({ ...loaded, credentials: [...config.credentials, ...loaded.credentials] });
    }
    fileError = false; renderSettings(); invalidate(); status('File loaded locally. Nothing was uploaded.');
  } catch { fileError = true; status('Invalid file. Load a valid file or clear the workspace before continuing. No credential values are shown.'); }
  finally { $(id).value = ''; $('sanitize').disabled = fileError; }
});
$('log-file').addEventListener('change', async () => {
  try { const text = await readSelectedFile($('log-file'), 10 * 1024 * 1024); if (text !== null) { $('input').value = text; $('input').dispatchEvent(new Event('input')); } }
  catch { status('Could not open log. Maximum file size is 10 MiB.'); }
  finally { $('log-file').value = ''; }
});
$('clear').addEventListener('click', () => { $('input').value = ''; $('input-count').textContent = '0 characters'; config = normalizeConfig(); fileError = false; $('sanitize').disabled = false; invalidate(); renderSettings(); status('Logs and custom credentials cleared from this page. Previously copied clipboard data and downloaded files are unaffected.'); });
try { config = normalizeConfig(await (await fetch('./config.json', { cache: 'no-store' })).json()); renderSettings(); }
catch { renderSettings(); $('sanitize').disabled = true; status('Could not load startup settings. Restart the GUI before processing logs.'); }
