/** Pure, offline redaction. No filesystem, network, logging, or persistent state. */
export const CATEGORY_NAMES = Object.freeze(['tokens', 'passwords', 'cookies', 'emails', 'phones', 'ipAddresses', 'userPaths', 'custom']);
const ACTIONS = ['label', 'mask', 'remove', 'replace'];
export const DEFAULT_CONFIG = Object.freeze({
  version: 1,
  action: 'label',
  categories: Object.freeze(Object.fromEntries(CATEGORY_NAMES.map(name => [name, Object.freeze({ enabled: !['phones', 'ipAddresses'].includes(name) })]))),
  sensitiveKeys: Object.freeze([]),
});
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const escapeRE = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function fail(message) { throw new TypeError(message); }
function keys(value, allowed, location) {
  if (!plain(value)) fail(`${location} must be an object.`);
  if (Object.keys(value).some(key => !allowed.includes(key))) fail(`${location} contains an unsupported property.`);
}
function policy(value, location) {
  keys(value, ['enabled', 'action', 'replacement'], location);
  if (value.enabled !== undefined && typeof value.enabled !== 'boolean') fail(`${location}.enabled must be boolean.`);
  if (value.action !== undefined && !ACTIONS.includes(value.action)) fail(`${location}.action is invalid.`);
  if (value.replacement !== undefined && typeof value.replacement !== 'string') fail(`${location}.replacement must be a string.`);
}
export function normalizeConfig(input = {}) {
  keys(input, ['version', 'action', 'replacement', 'categories', 'sensitiveKeys', 'credentials'], 'Configuration');
  if (input.version !== undefined && input.version !== 1) fail('Unsupported configuration version.');
  if (input.action !== undefined && !ACTIONS.includes(input.action)) fail('Configuration.action is invalid.');
  if (input.replacement !== undefined && typeof input.replacement !== 'string') fail('Configuration.replacement must be a string.');
  const categories = {};
  if (input.categories !== undefined) keys(input.categories, CATEGORY_NAMES, 'Configuration.categories');
  for (const name of CATEGORY_NAMES) {
    const item = input.categories?.[name] ?? {};
    policy(item, `Configuration.categories.${name}`);
    categories[name] = { ...DEFAULT_CONFIG.categories[name], ...item };
  }
  const sensitiveKeys = input.sensitiveKeys ?? [];
  if (!Array.isArray(sensitiveKeys) || sensitiveKeys.some(k => typeof k !== 'string' || !k.trim() || k.length > 128) || sensitiveKeys.length > 200) fail('sensitiveKeys must contain up to 200 nonempty strings (maximum 128 characters each).');
  const credentials = input.credentials ?? [];
  if (!Array.isArray(credentials) || credentials.length > 200) fail('credentials must be an array with at most 200 entries.');
  for (const item of credentials) {
    keys(item, ['name', 'value', 'action', 'replacement'], 'Credential');
    if (typeof item.name !== 'string' || !item.name.trim() || item.name.length > 128) fail('Credential.name must be a nonempty string (maximum 128 characters).');
    if (typeof item.value !== 'string' || item.value.length < 3 || item.value.length > 16384) fail('Credential.value must contain between 3 and 16384 characters.');
    policy({ action: item.action, replacement: item.replacement }, 'Credential');
  }
  const result = { version: 1, action: input.action ?? 'label', replacement: input.replacement ?? '[REDACTED]', categories, sensitiveKeys: [...sensitiveKeys], credentials: credentials.map(c => ({ ...c })) };
  for (const item of [result, ...Object.values(categories), ...credentials]) {
    if (item.action === 'replace' && item.replacement === undefined) fail('The replace action requires replacement text.');
  }
  return result;
}

const KEY_GROUPS = {
  passwords: ['password', 'passwd', 'pwd', 'client_secret', 'clientSecret', 'private_key', 'privateKey', 'secret'],
  tokens: ['access_token', 'accessToken', 'refresh_token', 'refreshToken', 'id_token', 'idToken', 'api_key', 'apikey', 'api-key', 'token', 'authorization', 'x-api-key', 'x-auth-token'],
  cookies: ['cookie', 'set-cookie'],
};

export function createSanitizer(options = {}) {
  const config = normalizeConfig(options);
  // Deliberately compile only trusted, escaped field names. No user-supplied regex.
  const groups = { ...KEY_GROUPS, custom: config.sensitiveKeys };
  const fieldPatterns = Object.entries(groups).map(([category, names]) => [category, names.length ? new RegExp(`(^|[\\s,{;&?])(?:"(?:${names.map(escapeRE).join('|')})"|'(?:${names.map(escapeRE).join('|')})'|(?:${names.map(escapeRE).join('|')}))\\s*[:=]\\s*("(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*'|[^\\s,;&}]+)`, 'gim') : null]);
  return {
    sanitize(text) {
      if (typeof text !== 'string') fail('Input must be a string.');
      if (text.length > 10 * 1024 * 1024) fail('Input exceeds the 10 MiB character limit. Split the log into smaller files.');
      const candidates = [];
      const jsonRegions = [];
      try { JSON.parse(text); jsonRegions.push({ start: 0, end: text.length }); }
      catch {
        let offset = 0;
        for (const line of text.split('\n')) {
          if (/^\s*[\[{]/.test(line)) {
            try { JSON.parse(line); jsonRegions.push({ start: offset, end: offset + line.length }); } catch { /* Plain text fallback. */ }
          }
          offset += line.length + 1;
        }
      }
      function add(start, end, category, extra = {}) {
        if (end > start && config.categories[category].enabled) {
          if (candidates.length >= 50000) fail('Too many findings. Split the log into smaller files.');
          candidates.push({ start, end, category, ...extra });
        }
      }
      function matches(regex, category, group = 0) {
        for (const match of text.matchAll(regex)) {
          const value = match[group];
          if (value) add(match.index + match[0].lastIndexOf(value), match.index + match[0].lastIndexOf(value) + value.length, category);
        }
      }
      for (const region of jsonRegions) {
        // Walk source tokens, retaining formatting and decoding escaped property names.
        const tokenPattern = /\s*("(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\]:,])/gy;
        const tokens = []; let token;
        const source = text.slice(region.start, region.end);
        while ((token = tokenPattern.exec(source))) tokens.push({ raw: token[1], start: region.start + token.index + token[0].length - token[1].length, end: region.start + tokenPattern.lastIndex });
        let index = 0;
        function value() {
          const first = tokens[index++];
          if (first.raw === '{') {
            while (tokens[index].raw !== '}') {
              const key = JSON.parse(tokens[index++].raw).toLowerCase(); index++; // colon
              const child = value();
              const category = Object.entries(groups).find(([name, names]) => config.categories[name].enabled && names.some(n => n.toLowerCase() === key))?.[0];
              if (category) {
                const quoted = text[child.start] === '"';
                add(child.start + (quoted ? 1 : 0), child.end - (quoted ? 1 : 0), category, { jsonQuoted: quoted, priority: 6 });
              }
              if (tokens[index].raw === ',') index++;
            }
            const last = tokens[index++]; return { start: first.start, end: last.end };
          }
          if (first.raw === '[') {
            while (tokens[index].raw !== ']') { value(); if (tokens[index].raw === ',') index++; }
            const last = tokens[index++]; return { start: first.start, end: last.end };
          }
          return { start: first.start, end: first.end };
        }
        value();
      }
      for (const [category, regex] of fieldPatterns) {
        if (!regex || !config.categories[category].enabled) continue;
        for (const match of text.matchAll(regex)) {
          if (jsonRegions.some(r => match.index >= r.start && match.index < r.end)) continue;
          const raw = match[2];
          let start = match.index + match[0].length - raw.length;
          let end = start + raw.length;
          const jsonQuoted = raw.startsWith('"');
          if (jsonQuoted || raw.startsWith("'")) { start++; end--; }
          if (category === 'tokens' && /^(?:Bearer|Basic)$/i.test(raw)) continue;
          add(start, end, category, { jsonQuoted, priority: 3 });
        }
      }
      matches(/\b(?:Bearer|Basic)\s+([^\s"',;\\]+)/gi, 'tokens', 1);
      matches(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, 'tokens');
      matches(/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|sk_live_[A-Za-z0-9]{16,})\b/g, 'tokens');
      matches(/-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----/g, 'passwords');
      matches(/\b[A-Z0-9._%+-]+@[A-Z0-9](?:[A-Z0-9.-]*[A-Z0-9])?\.[A-Z]{2,}\b/gi, 'emails');
      matches(/(?<![\w])\+?\d[\d ()-]{7,}\d(?![\w])/g, 'phones');
      matches(/\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g, 'ipAddresses');
      matches(/(?:\/Users\/|\/home\/)[^\s/"'\\]+|[A-Za-z]:\\Users\\[^\s\\/"']+/gi, 'userPaths');
      matches(/[A-Za-z]:\\\\Users\\\\[^\s\\/"']+/gi, 'userPaths');
      // Cookie headers may contain multiple values separated by spaces or semicolons.
      for (const match of text.matchAll(/^(\s*(?:Set-Cookie|Cookie)\s*:\s*)([^\r\n]+)/gim)) add(match.index + match[1].length, match.index + match[0].length, 'cookies', { priority: 4 });
      // Remove URL userinfo while leaving host/path useful for troubleshooting.
      matches(/\b[a-z][a-z0-9+.-]*:\/\/([^\s/@]+(?::[^\s/@]*)?)@/gi, 'passwords', 1);
      for (const credential of config.credentials) {
        if (!config.categories.custom.enabled) continue;
        const values = new Set([credential.value, JSON.stringify(credential.value).slice(1, -1)]);
        for (const value of values) {
          let offset = 0;
          while ((offset = text.indexOf(value, offset)) !== -1) {
            add(offset, offset + value.length, 'custom', { action: credential.action, replacement: credential.replacement, priority: 7, identity: credential.value, jsonQuoted: value !== credential.value });
            offset += value.length;
          }
        }
      }
      // Merge intersecting spans rather than allowing a shorter match to expose a suffix.
      candidates.sort((a, b) => a.start - b.start || b.end - a.end || (b.priority ?? 0) - (a.priority ?? 0));
      const spans = [];
      for (const candidate of candidates) {
        const last = spans.at(-1);
        if (!last || candidate.start >= last.end) { spans.push({ ...candidate }); continue; }
        const end = Math.max(last.end, candidate.end);
        if ((candidate.priority ?? 0) > (last.priority ?? 0)) {
          const start = last.start;
          Object.assign(last, candidate, { start });
        }
        last.end = end;
      }
      const labels = new Map();
      const jsonStrings = jsonRegions.flatMap(r => [...text.slice(r.start, r.end).matchAll(/"(?:\\.|[^"\\])*"/g)].map(m => ({ start: r.start + m.index + 1, end: r.start + m.index + m[0].length - 1 })));
      const counters = {};
      const summary = {};
      const findings = [];
      let output = '', cursor = 0;
      for (const span of spans) {
        const original = text.slice(span.start, span.end);
        const settings = config.categories[span.category];
        const action = span.action ?? settings.action ?? config.action;
        let replacement;
        if (action === 'mask') replacement = '********';
        else if (action === 'remove') replacement = '';
        else if (action === 'replace') replacement = span.replacement ?? settings.replacement ?? config.replacement;
        else {
          const key = `${span.category}\0${span.identity ?? original}`;
          if (!labels.has(key)) {
            counters[span.category] = (counters[span.category] ?? 0) + 1;
            labels.set(key, `<${span.category.replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase()}_${counters[span.category]}>`);
          }
          replacement = labels.get(key);
        }
        const insideJsonString = jsonStrings.some(s => span.start >= s.start && span.end <= s.end);
        const insideJsonRegion = jsonRegions.some(r => span.start >= r.start && span.end <= r.end);
        if (insideJsonString || span.jsonQuoted && !insideJsonRegion) replacement = JSON.stringify(replacement).slice(1, -1);
        else if (insideJsonRegion) replacement = JSON.stringify(replacement);
        output += text.slice(cursor, span.start);
        const outputStart = output.length;
        output += replacement;
        findings.push({ category: span.category, start: span.start, end: span.end, outputStart, outputEnd: output.length, action });
        summary[span.category] = (summary[span.category] ?? 0) + 1;
        cursor = span.end;
      }
      output += text.slice(cursor);
      // Unexpected matches crossing JSON syntax must fail closed, never emit broken records.
      for (const region of jsonRegions) {
        if (findings.some(f => f.start < region.start && f.end > region.start || f.start < region.end && f.end > region.end)) fail('A redaction crosses structured record boundaries. Process records separately.');
        const shifted = position => position + findings.filter(f => f.end <= position).reduce((sum, f) => sum + (f.outputEnd - f.outputStart) - (f.end - f.start), 0);
        try { JSON.parse(output.slice(shifted(region.start), shifted(region.end))); }
        catch { fail('Redaction would invalidate structured input. Adjust the custom rules before sharing.'); }
      }
      return { text: output, findings, summary, total: findings.length };
    },
  };
}
export function sanitize(text, options) { return createSanitizer(options).sanitize(text); }
