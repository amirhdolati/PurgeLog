import { emitKeypressEvents } from 'node:readline';
import { lstat } from 'node:fs/promises';
import { CATEGORY_NAMES, normalizeConfig } from './core/index.js';
import { readConfigFile, saveConfig } from './config.js';

export async function runSettings(path = 'purgelog.json') {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('Settings requires an interactive terminal. Use a JSON config in scripts.');
  // Existing settings are replaced only after a separate explicit confirmation.
  let config;
  let exists = false;
  try { await lstat(path); exists = true; } catch (error) { if (error.code !== 'ENOENT') throw new Error('Could not access settings.'); }
  config = exists ? await readConfigFile(path) : normalizeConfig();
  if (config.credentials.length) throw new Error('Use a settings file without credentials.');
  let selected = 0;
  let confirming = false;
  const actions = ['label', 'mask', 'remove', 'replace'];
  const render = () => {
    process.stdout.write('\x1b[2J\x1b[H');
    process.stdout.write('PurgeLog settings\n\nUp/Down: navigate  Space: toggle  Left/Right: category action\nEnter: save  Esc: cancel\n\n');
    CATEGORY_NAMES.forEach((name, i) => process.stdout.write(`${selected === i ? '>' : ' '} [${config.categories[name].enabled ? 'x' : ' '}] ${name}: ${config.categories[name].action ?? 'default'}\n`));
    process.stdout.write(`\n${selected === CATEGORY_NAMES.length ? '>' : ' '} Default action: ${config.action} (Space to cycle)\n`);
    process.stdout.write(confirming ? '\nReplace the existing settings file? Press Y to save, N to return.\n' : '\nCustom replacement text can be edited in the JSON settings file.\n');
  };
  emitKeypressEvents(process.stdin); process.stdin.setRawMode(true); process.stdin.resume();
  process.stdout.write('\x1b[?25l'); render();
  await new Promise((done, reject) => {
    let finished = false;
    const cleanup = () => { finished = true; process.stdin.off('keypress', handler); process.stdin.setRawMode(false); process.stdin.pause(); process.stdout.write('\x1b[?25h\x1b[2J\x1b[H'); };
    const handler = async (_, key = {}) => {
      if (finished) return;
      if (key.name === 'escape' || (key.ctrl && key.name === 'c')) { cleanup(); done(); return; }
      if (confirming && key.name !== 'y') { if (key.name === 'n') confirming = false; render(); return; }
      if (key.name === 'up') selected = (selected + CATEGORY_NAMES.length) % (CATEGORY_NAMES.length + 1);
      if (key.name === 'down') selected = (selected + 1) % (CATEGORY_NAMES.length + 1);
      if (key.name === 'space') {
        if (selected < CATEGORY_NAMES.length) config.categories[CATEGORY_NAMES[selected]].enabled = !config.categories[CATEGORY_NAMES[selected]].enabled;
        else config.action = actions[(actions.indexOf(config.action) + 1) % actions.length];
      }
      if (['left', 'right'].includes(key.name) && selected < CATEGORY_NAMES.length) {
        const category = config.categories[CATEGORY_NAMES[selected]];
        const choices = [undefined, ...actions];
        category.action = choices[(choices.indexOf(category.action) + (key.name === 'right' ? 1 : choices.length - 1)) % choices.length];
        if (category.action === undefined) delete category.action;
        if (category.action === 'replace') category.replacement ??= config.replacement;
      }
      if (key.name === 'return' && exists && !confirming) { confirming = true; render(); return; }
      if (key.name === 'return' || confirming && key.name === 'y') {
        cleanup();
        try { await saveConfig(path, config, { overwrite: exists }); process.stdout.write('Settings saved.\n'); done(); }
        catch { reject(new Error('Could not create settings. Choose a new path with --config; existing files are never overwritten.')); }
        return;
      }
      render();
    };
    process.stdin.on('keypress', handler);
  });
}
