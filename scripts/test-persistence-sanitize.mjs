#!/usr/bin/env node
// Self-test for the storage-state size cap in lib/persistence.js.
//
//   node scripts/test-persistence-sanitize.mjs
//
// Covers the regression that made every session creation fail with
// "Unable to restore IndexedDB" once ChatGPT wrote a multi-MB localStorage
// entry: the snapshot must be pruned on write and on load.

import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  DEFAULT_MAX_STORAGE_ITEM_BYTES,
  getUserPersistencePaths,
  loadPersistedStorageState,
  persistStorageState,
  sanitizeStorageState,
} from '../lib/persistence.js';

const warnings = [];
const logger = { warn: (msg, fields) => warnings.push({ msg, fields }) };

const cookie = (...args) => ({
  name: args[0],
  value: args[1] ?? 'v',
  domain: '.example.com',
  path: '/',
  expires: -1,
  httpOnly: true,
  secure: true,
  sameSite: 'Lax',
});

const bigValue = 'x'.repeat(4 * 1024 * 1024);
const sample = {
  cookies: [cookie('session', 'secret'), cookie('other', 'second')],
  origins: [
    {
      origin: 'https://example.com',
      localStorage: [
        { name: 'small', value: 'kept' },
        { name: 'statsig.cached.evaluations.1', value: bigValue },
      ],
      indexedDB: [
        { name: 'db', version: 1, stores: [{ name: 's', records: [{ key: 'k', value: 'v' }] }] },
      ],
    },
    { origin: 'https://empty.example', localStorage: [] },
  ],
};

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

test('drops oversized localStorage entries but keeps the rest', () => {
  const out = sanitizeStorageState(sample, { logger, userId: 'u1' });
  assert.deepEqual(out.cookies.map((c) => c.name), ['session', 'other']);
  const origins = out.origins;
  assert.equal(origins.length, 1, 'origin without content is dropped');
  assert.equal(origins[0].origin, 'https://example.com');
  assert.deepEqual(origins[0].localStorage, [{ name: 'small', value: 'kept' }]);
  assert.equal(origins[0].indexedDB, undefined, 'IndexedDB is dropped unless opted in');
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0].fields.count, 1);
  assert.equal(warnings[0].fields.maxItemBytes, DEFAULT_MAX_STORAGE_ITEM_BYTES);
  assert.equal(warnings[0].fields.entries[0].name, 'statsig.cached.evaluations.1');
});

test('honours the size threshold including its boundary', () => {
  const exact = { cookies: [], origins: [{ origin: 'https://a.test', localStorage: [{ name: 'k', value: 'v'.repeat(9) }] }] };
  assert.equal(sanitizeStorageState(exact, { maxItemBytes: 10 }).origins.length, 1, '10 bytes fits in 10');
  assert.equal(sanitizeStorageState(exact, { maxItemBytes: 9 }).origins.length, 0, '10 bytes exceeds 9');
  assert.equal(sanitizeStorageState(exact, { maxItemBytes: 0 }).origins.length, 1, '0 disables the cap');
});

test('keeps IndexedDB when explicitly requested', () => {
  const out = sanitizeStorageState(sample, { keepIndexedDB: true, logger });
  assert.equal(out.origins[0].indexedDB.length, 1);
});

test('tolerates malformed input', () => {
  assert.equal(sanitizeStorageState(null), null);
  const out = sanitizeStorageState({ origins: 'nope' }, {});
  assert.deepEqual(out, { origins: [], cookies: [] });
});

test('persist drops oversized entries and keeps cookies', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'camofox-persist-'));
  await persistStorageState({ profileDir: dir, userId: 'u1', storageState: sample, logger });
  const { storageStatePath } = getUserPersistencePaths(dir, 'u1');
  const written = JSON.parse(await fs.readFile(storageStatePath, 'utf8'));
  assert.equal(written.cookies.length, 2);
  assert.deepEqual(written.origins[0].localStorage, [{ name: 'small', value: 'kept' }]);
  assert.ok((await fs.stat(storageStatePath)).size < 4096, 'snapshot stays small');
});

test('load prunes a previously oversized snapshot in place', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'camofox-heal-'));
  const { storageStatePath } = getUserPersistencePaths(dir, 'u1');
  await fs.mkdir(path.dirname(storageStatePath), { recursive: true });
  await fs.writeFile(storageStatePath, JSON.stringify(sample, null, 2));

  const loaded = await loadPersistedStorageState(dir, 'u1', logger);
  assert.equal(loaded, storageStatePath);
  const healed = JSON.parse(await fs.readFile(storageStatePath, 'utf8'));
  assert.deepEqual(healed.origins[0].localStorage, [{ name: 'small', value: 'kept' }]);
  assert.equal(healed.cookies.length, 2);
  assert.ok(warnings.some((w) => w.msg === 'pruned persisted storage state on load'));
});

test('load leaves a clean snapshot untouched', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'camofox-clean-'));
  const { storageStatePath } = getUserPersistencePaths(dir, 'u1');
  await fs.mkdir(path.dirname(storageStatePath), { recursive: true });
  const clean = { cookies: [cookie('session')], origins: [{ origin: 'https://example.com', localStorage: [{ name: 'a', value: 'b' }] }] };
  await fs.writeFile(storageStatePath, JSON.stringify(clean, null, 2));
  const before = await fs.stat(storageStatePath);
  await loadPersistedStorageState(dir, 'u1', logger);
  const after = await fs.stat(storageStatePath);
  assert.equal(before.mtimeMs, after.mtimeMs, 'file is not rewritten');
});

let failed = 0;
for (const { name, fn } of tests) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (err) {
    failed += 1;
    console.log(`FAIL ${name}`);
    console.log('     ' + String(err.message).split('\n').join('\n     '));
  }
}

console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed === 0 ? 0 : 1);
