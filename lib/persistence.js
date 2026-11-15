import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

function getUserPersistencePaths(profileDir, userId) {
  const rootDir = path.resolve(profileDir);
  const safeUserDir = crypto
    .createHash('sha256')
    .update(String(userId))
    .digest('hex')
    .slice(0, 32);

  const userDir = path.join(rootDir, safeUserDir);
  return {
    rootDir,
    userDir,
    storageStatePath: path.join(userDir, 'storage-state.json'),
    metaPath: path.join(userDir, 'meta.json'),
  };
}

async function loadPersistedStorageState(profileDir, userId, logger = console) {
  if (!profileDir) return undefined;

  const { storageStatePath } = getUserPersistencePaths(profileDir, userId);

  try {
    const raw = await fs.readFile(storageStatePath, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return undefined;
    if (!Array.isArray(parsed.cookies)) return undefined;
    if (parsed.origins !== undefined && !Array.isArray(parsed.origins)) return undefined;

    // Self-heal snapshots written before the size cap existed: an oversized
    // entry here fails every later session creation, so prune it on the way in
    // and persist the smaller snapshot so the fix sticks.
    const sanitized = sanitizeStorageState(parsed, { logger, userId });
    const next = JSON.stringify(sanitized, null, 2);
    if (next !== raw) {
      const tmpPath = `${storageStatePath}.tmp-${process.pid}-${Date.now()}`;
      await fs.writeFile(tmpPath, next).then(() => fs.rename(tmpPath, storageStatePath));
      logger?.warn?.('pruned persisted storage state on load', {
        userId: String(userId),
        storageStatePath,
        bytesBefore: Buffer.byteLength(raw, 'utf8'),
        bytesAfter: Buffer.byteLength(next, 'utf8'),
      });
    }
    return storageStatePath;
  } catch (err) {
    if (err?.code === 'ENOENT') return undefined;
    logger?.warn?.('failed to load persisted storage state', {
      userId: String(userId),
      storageStatePath,
      error: err?.message || String(err),
    });
    return undefined;
  }
}

// Per-origin localStorage quota in Firefox is small (a few MiB). Applications
// like ChatGPT happily write multi-MB telemetry blobs (statsig evaluation
// caches) into localStorage, which makes the snapshot grow past that quota.
// Restoring such a snapshot then fails with a generic error:
//
//   browser.newContext: Error setting storage state:
//   Unable to restore IndexedDB: The operation failed for reasons unrelated to
//   the database itself and not covered by any other error code.
//
// The session then cannot be created at all, and because persistence keeps
// re-saving the same huge snapshot, every later session fails until the browser
// process is restarted. Login state lives in cookies, not in those blobs, so a
// size cap is safe: oversized entries are dropped on write and the snapshot
// stays small and restorable.
const DEFAULT_MAX_STORAGE_ITEM_BYTES = 256 * 1024;

function maxStorageItemBytes() {
  const raw = process.env.CAMOFOX_PERSIST_MAX_ITEM_BYTES;
  const parsed = Number.parseInt(raw ?? '', 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : DEFAULT_MAX_STORAGE_ITEM_BYTES;
}

function itemBytes(entry) {
  const name = String(entry?.name ?? '');
  const value = String(entry?.value ?? '');
  return Buffer.byteLength(name, 'utf8') + Buffer.byteLength(value, 'utf8');
}

/**
 * Drop storage-state content that cannot be restored or is not worth keeping.
 *
 * - localStorage entries larger than `maxItemBytes` (default 256 KiB) are
 *   removed; a warning with the affected names is logged.
 * - IndexedDB payloads are removed unless the caller opted in.
 * - origins left without localStorage and without IndexedDB are dropped.
 * - cookies are always kept untouched.
 */
function sanitizeStorageState(state, { maxItemBytes = maxStorageItemBytes(), keepIndexedDB = false, logger, userId } = {}) {
  if (!state || typeof state !== 'object') return state;

  const dropped = [];
  const origins = [];

  for (const origin of Array.isArray(state.origins) ? state.origins : []) {
    if (!origin || typeof origin !== 'object') continue;
    const localStorage = Array.isArray(origin.localStorage)
      ? origin.localStorage.filter((entry) => {
          if (!entry || typeof entry !== 'object') return false;
          const size = itemBytes(entry);
          if (maxItemBytes > 0 && size > maxItemBytes) {
            dropped.push({ origin: origin.origin, name: String(entry.name ?? ''), bytes: size });
            return false;
          }
          return true;
        })
      : [];
    const indexedDB = keepIndexedDB && Array.isArray(origin.indexedDB) ? origin.indexedDB : [];
    if (localStorage.length === 0 && indexedDB.length === 0) continue;
    const next = { ...origin, localStorage };
    if (keepIndexedDB) next.indexedDB = indexedDB;
    else delete next.indexedDB;
    origins.push(next);
  }

  if (dropped.length > 0) {
    logger?.warn?.('dropped oversized localStorage entries from storage state', {
      userId: userId === undefined ? undefined : String(userId),
      count: dropped.length,
      maxItemBytes,
      entries: dropped.slice(0, 5),
    });
  }

  return {
    ...state,
    cookies: Array.isArray(state.cookies) ? state.cookies : [],
    origins,
  };
}

async function persistStorageState({
  profileDir,
  userId,
  context,
  storageState,
  logger = console,
  indexedDB = false,
}) {
  if (!profileDir || (!context && !storageState)) {
    return { persisted: false, reason: 'disabled' };
  }

  const { userDir, storageStatePath, metaPath } = getUserPersistencePaths(profileDir, userId);
  const suffix = `.tmp-${process.pid}-${Date.now()}`;
  const tmpStoragePath = `${storageStatePath}${suffix}`;
  const tmpMetaPath = `${metaPath}${suffix}`;

  try {
    await fs.mkdir(userDir, { recursive: true });
    const captured = storageState || (await context.storageState(indexedDB ? { indexedDB: true } : undefined));
    const sanitized = sanitizeStorageState(captured, { keepIndexedDB: indexedDB, logger, userId });
    await fs.writeFile(tmpStoragePath, JSON.stringify(sanitized, null, 2));
    await fs.rename(tmpStoragePath, storageStatePath);
    await fs.writeFile(
      tmpMetaPath,
      JSON.stringify(
        {
          userId: String(userId),
          updatedAt: new Date().toISOString(),
          storageStatePath,
        },
        null,
        2
      )
    );
    await fs.rename(tmpMetaPath, metaPath);
    return { persisted: true, userDir, storageStatePath, metaPath };
  } catch (err) {
    await fs.unlink(tmpStoragePath).catch(() => {});
    await fs.unlink(tmpMetaPath).catch(() => {});
    logger?.warn?.('failed to persist storage state', {
      userId: String(userId),
      storageStatePath,
      error: err?.message || String(err),
    });
    return { persisted: false, reason: 'error', error: err };
  }
}

export {
  DEFAULT_MAX_STORAGE_ITEM_BYTES,
  getUserPersistencePaths,
  loadPersistedStorageState,
  persistStorageState,
  sanitizeStorageState,
};
