import assert from 'node:assert/strict';
import test from 'node:test';

import { parseByteRange } from '../src/utils/http-range.js';

test('returns none when no Range header is present', () => {
  assert.deepEqual(parseByteRange(undefined, 1000), { kind: 'none' });
});

test('parses bounded and open-ended byte ranges', () => {
  assert.deepEqual(parseByteRange('bytes=100-199', 1000), {
    kind: 'range',
    start: 100,
    end: 199,
  });
  assert.deepEqual(parseByteRange('bytes=250-', 1000), {
    kind: 'range',
    start: 250,
    end: 999,
  });
});

test('clamps an end offset beyond the chunk length', () => {
  assert.deepEqual(parseByteRange('bytes=900-1200', 1000), {
    kind: 'range',
    start: 900,
    end: 999,
  });
});

test('parses suffix byte ranges', () => {
  assert.deepEqual(parseByteRange('bytes=-250', 1000), {
    kind: 'range',
    start: 750,
    end: 999,
  });
  assert.deepEqual(parseByteRange('bytes=-2000', 1000), {
    kind: 'range',
    start: 0,
    end: 999,
  });
});

test('rejects malformed, multiple, empty, and unsatisfiable ranges', () => {
  for (const value of [
    'items=0-1',
    'bytes=0-1,3-4',
    'bytes=-',
    'bytes=-0',
    'bytes=1000-',
    'bytes=500-499',
  ]) {
    assert.deepEqual(parseByteRange(value, 1000), { kind: 'invalid' });
  }
});
