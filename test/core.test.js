import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitize, createSanitizer, normalizeConfig } from '../src/core/index.js';

test('redacts field values and preserves useful context', () => {
  assert.equal(sanitize('password=top-secret email=alice@example.com status=500').text, 'password=<PASSWORDS_1> email=<EMAILS_1> status=500');
});
test('authorization scheme is preserved, secret is removed', () => {
  const result = sanitize('Authorization: Bearer abc-secret');
  assert.equal(result.text, 'Authorization: Bearer <TOKENS_1>');
});
test('same value has stable labels per call, no cross-call numbering', () => {
  const cleaner = createSanitizer();
  assert.equal(cleaner.sanitize('a@example.com b@example.com a@example.com').text, '<EMAILS_1> <EMAILS_2> <EMAILS_1>');
  assert.equal(cleaner.sanitize('b@example.com').text, '<EMAILS_1>');
});
test('JSON remains valid with escapes, nested objects and Unicode', () => {
  const input = JSON.stringify({ text: 'سلام دنیا', nested: { password: 'line\nquote"secret', email: 'a@example.com' } });
  const output = JSON.parse(sanitize(input).text);
  assert.equal(output.text, 'سلام دنیا');
  assert.equal(output.nested.password, '<PASSWORDS_1>');
});
test('numeric sensitive JSON values become valid string replacements', () => {
  assert.deepEqual(JSON.parse(sanitize('{"password":12345}').text), { password: '<PASSWORDS_1>' });
});
test('custom replacement is JSON-escaped for an email match', () => {
  const output = sanitize('{"email":"a@example.com"}', { action: 'replace', replacement: 'quote"\n' });
  assert.equal(JSON.parse(output.text).email, 'quote"\n');
});
test('fixed mask does not reveal original value length', () => {
  assert.equal(sanitize('password=abc token=verylongpassword', { action: 'mask' }).text, 'password=******** token=********');
});
test('remove clears a value and preserves JSON', () => {
  assert.equal(JSON.parse(sanitize('{"password":"secret"}', { action: 'remove' }).text).password, '');
});
test('category overrides take precedence over the default', () => {
  assert.equal(sanitize('password=secret a@example.com', { categories: { emails: { action: 'mask' } } }).text, 'password=<PASSWORDS_1> ********');
});
test('disabled categories leave matching values unchanged', () => {
  assert.equal(sanitize('a@example.com', { categories: { emails: { enabled: false } } }).text, 'a@example.com');
});
test('phone and IP categories are opt in', () => {
  const input = '+1 202 555 0198 192.168.1.1';
  assert.equal(sanitize(input).text, input);
  assert(!sanitize('192.168.1.1', { categories: { ipAddresses: { enabled: true } } }).text.includes('192.168.1.1'));
});
test('custom keys are escaped and case insensitive', () => {
  assert.equal(sanitize('CUSTOM.KEY="private value"', { sensitiveKeys: ['custom.key'] }).text, 'CUSTOM.KEY="<CUSTOM_1>"');
});
test('exact custom credentials are literal, not regex', () => {
  assert.equal(sanitize('key=a.b+c aXbYc', { credentials: [{ name: 'demo', value: 'a.b+c' }] }).text, 'key=<CUSTOM_1> aXbYc');
});
test('JSON-escaped custom credentials are recognized', () => {
  const secret = 'a"b\\c';
  const output = sanitize(JSON.stringify({ message: secret }), { credentials: [{ name: 'demo', value: secret }] });
  assert.equal(JSON.parse(output.text).message, '<CUSTOM_1>');
});
test('overlapping custom and field matches cannot expose a suffix', () => {
  const output = sanitize('password=abcdefgh', { credentials: [{ name: 'partial', value: 'abc' }] });
  assert(!output.text.includes('defgh')); assert.equal(output.total, 1);
});
test('cookie header redacts all values', () => {
  assert.equal(sanitize('Cookie: session=secret; other=private\nnext=line').text, 'Cookie: <COOKIES_1>\nnext=line');
});
test('URL credentials and sensitive query values are redacted', () => {
  const out = sanitize('https://alice:password@example.com/path?api_key=private&ok=true').text;
  assert(!out.includes('alice:password')); assert(!out.includes('private')); assert(out.includes('ok=true'));
});
test('personal paths keep the remainder', () => {
  assert.equal(sanitize('/Users/alice/project/file.js C:\\Users\\bob\\work').text, '<USER_PATHS_1>/project/file.js <USER_PATHS_2>\\work');
});
test('private key blocks are redacted including newlines', () => {
  assert.equal(sanitize('-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----').text, '<PASSWORDS_1>');
});
test('reports contain positions and counts, never original credential values or names', () => {
  const result = sanitize('secret-xyz', { credentials: [{ name: 'private-name', value: 'secret-xyz' }] });
  assert(!JSON.stringify(result).includes('secret-xyz')); assert(!JSON.stringify(result).includes('private-name'));
  assert.equal(result.text.slice(result.findings[0].outputStart, result.findings[0].outputEnd), '<CUSTOM_1>');
});
test('invalid config cannot leak provided values through errors', () => {
  for (const config of [{ credentials: [{ name: 's', value: 'xy' }] }, { action: 'bad-secret' }, { categories: { bogus: {} } }, { version: 2 }]) {
    assert.throws(() => normalizeConfig(config), error => !error.message.includes('bad-secret'));
  }
});
test('oversized input is rejected', () => { assert.throws(() => sanitize('x'.repeat(10 * 1024 * 1024 + 1)), /limit/); });
test('input configuration is copied, never mutated', () => {
  const config = { categories: { emails: { enabled: true } } }; const snapshot = JSON.stringify(config);
  createSanitizer(config).sanitize('a@example.com'); assert.equal(JSON.stringify(config), snapshot);
});
