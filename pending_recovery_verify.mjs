import {createHash} from 'node:crypto';
import {RECOVERY_IDENTITY} from './pending_recovery.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PROMPT = 'Synthetic sandbox diagnostic sandbox-ping-20261014-062904. Reply with exactly SANDBOX_OK.';
const KEYS = ['userId', 'tabId', 'threadId', 'url', 'operationId', 'sessionKey', 'prompt', 'page'];
const failClosed = () => false;
const exactKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function validObservation(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.ok !== true ||
      value.thread_id !== RECOVERY_IDENTITY.threadId || typeof value.complete !== 'boolean') return false;
  if (!value.complete) return exactKeys(value, ['ok', 'thread_id', 'complete']);
  return exactKeys(value, ['ok', 'thread_id', 'complete', 'output', 'truncated']) &&
    typeof value.output === 'string' && value.output.length <= 4096 && typeof value.truncated === 'boolean';
}

// domSource must be trusted, captured adapter bytes supplied by the build/runtime owner.
// It is never read from caller arguments or loaded from a mutable path at runtime.
export function makePendingRecoveryVerifier({domSource} = {}) {
  if (typeof domSource !== 'string' || domSource.length === 0 || domSource.length > 100_000)
    throw Error('pending_recovery_dom_source_invalid');
  const expression = `(${domSource})('observe',${JSON.stringify(RECOVERY_IDENTITY.threadId)},[${JSON.stringify(PROMPT)}],null)`;

  return async function verifyReadOnly(args) {
    if (!exactKeys(args, KEYS) || args.userId !== RECOVERY_IDENTITY.userId ||
        args.operationId !== RECOVERY_IDENTITY.operationId || args.sessionKey !== RECOVERY_IDENTITY.sessionKey ||
        args.threadId !== RECOVERY_IDENTITY.threadId || args.url !== RECOVERY_IDENTITY.url ||
        args.prompt !== PROMPT || typeof args.tabId !== 'string' || !UUID.test(args.tabId) ||
        !args.page || typeof args.page.url !== 'function' || typeof args.page.evaluate !== 'function') return false;
    try {
      if (args.page.url() !== RECOVERY_IDENTITY.url) return false;
      const observed = await args.page.evaluate(expression);
      if (!validObservation(observed)) return false;
      return args.page.url() === RECOVERY_IDENTITY.url;
    } catch {
      return failClosed();
    }
  };
}

export function makePinnedPendingRecoveryVerifier({domSource, domSha256} = {}) {
  if (typeof domSource !== 'string' || typeof domSha256 !== 'string' ||
      !/^[0-9a-f]{64}$/.test(domSha256) ||
      createHash('sha256').update(domSource, 'utf8').digest('hex') !== domSha256)
    throw Error('pending_recovery_dom_integrity_invalid');
  return makePendingRecoveryVerifier({domSource});
}

export {PROMPT as PENDING_RECOVERY_DIAGNOSTIC_PROMPT};
