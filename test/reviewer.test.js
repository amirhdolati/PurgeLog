import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitize } from '../src/core/index.js';

test('review: sensitive JSON object values are redacted as a whole', () => {
  const result = sanitize('{"password":{"a":"secret","b":"leak"},"safe":"keep"}');
  assert.equal(JSON.parse(result.text).safe, 'keep');
  assert(!result.text.includes('secret'));
  assert(!result.text.includes('leak'));
});

test('review: sensitive JSON arrays cannot leave trailing elements', () => {
  const result = sanitize('{"token":["one","two"],"safe":42}');
  assert.equal(JSON.parse(result.text).safe, 42);
  assert(!result.text.includes('one'));
  assert(!result.text.includes('two'));
});

test('review: escaped JSON keys still match sensitive field rules', () => {
  const result = sanitize('{"pass\\u0077ord":"private-value"}');
  assert(!result.text.includes('private-value'));
  assert.equal(typeof JSON.parse(result.text).password, 'string');
});

test('review: escaped Windows user paths do not leak username in JSON', () => {
  const result = sanitize(JSON.stringify({ path: 'C:\\Users\\private-user\\project' }));
  const output = JSON.parse(result.text);
  assert(!output.path.includes('private-user'));
  assert(output.path.includes('project'));
});

test('review: custom credential replacement does not corrupt JSON string escaping', () => {
  const result = sanitize('{"message":"prefix abc-secret suffix"}', {
    credentials: [{ name: 'synthetic', value: 'abc-secret', action: 'replace', replacement: 'quote"\n' }],
  });
  assert.equal(JSON.parse(result.text).message, 'prefix quote"\n suffix');
});

test('review: overlapping custom credentials remove their entire union', () => {
  const result = sanitize('abcdefg', {
    credentials: [{ name: 'left', value: 'abcde' }, { name: 'right', value: 'cdefg' }],
  });
  assert.equal(result.total, 1);
  assert(!result.text.includes('fg'));
  assert(!result.text.includes('ab'));
});

test('review: explicit credential action takes precedence inside a sensitive JSON field', () => {
  const result = sanitize('{"token":"abc-secret"}', {
    credentials: [{ name: 'synthetic', value: 'abc-secret', action: 'mask' }],
  });
  assert.equal(JSON.parse(result.text).token, '********');
});

test('review: numeric secrets in JSON Lines preserve valid line structure', () => {
  const result = sanitize('{"token":123}\n{"password":456}\n');
  const lines = result.text.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(typeof lines[0].token, 'string');
  assert.equal(typeof lines[1].password, 'string');
});

test('review: encoded custom credential overlapping a sensitive container preserves JSON', () => {
  for (const value of [{ child: 'a"b' }, ['a"b']]) {
    const input = JSON.stringify({ password: value, safe: 42 });
    const result = sanitize(input, { credentials: [{ name: 'synthetic', value: 'a"b' }] });
    assert.equal(JSON.parse(result.text).safe, 42);
    assert(!result.text.includes('child'));
    assert(!result.text.includes('a\\"b'));
  }
});
