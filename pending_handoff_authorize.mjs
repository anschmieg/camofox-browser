import {RECOVERY_IDENTITY} from './pending_recovery.mjs';

const OPERATION_ID = RECOVERY_IDENTITY.operationId;
const THREAD_ID = RECOVERY_IDENTITY.threadId;
const USER_ID = RECOVERY_IDENTITY.userId;
const SESSION_KEY = RECOVERY_IDENTITY.sessionKey;
const URL = RECOVERY_IDENTITY.url;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE = /^[0-9a-f]{64}$/;
const POLICY_KEYS = ['version', 'authorized_uid', 'user_id', 'session_key', 'max_messages', 'issued_unix', 'expires_unix', 'project_creation', 'personal_content', 'arbitrary_code', 'work_mode'];
const JOURNAL_KEYS = ['version', 'paused', 'tab_id', 'thread_id', 'operations'];
const OP_KEYS = ['operation_id', 'test', 'phase', 'nonce'];
const GUARD_KEYS = ['version', 'operationId', 'nonce', 'enrollment'];
const ENROLLMENT_KEYS = ['userId', 'tabIds'];
const APPROVAL_KEYS = ['version', 'operation_id', 'original_tab_id', 'replacement_tab_id', 'thread_id', 'user_id', 'session_key', 'observe_only', 'issued_unix', 'expires_unix'];
const HANDOFF_KEYS = ['version', 'operation_id', 'nonce', 'original_tab_id', 'replacement_tab_id', 'thread_id', 'phase'];
const RECOVERY_KEYS = ['version', 'operationId', 'userId', 'sessionKey', 'originalTabId', 'threadId', 'url', 'nonce', 'phase', 'tabId'];
const keysAre = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
const int = Number.isSafeInteger;

function validate(s, request, now) {
  if (!keysAre(s, ['policy', 'journal', 'guard', 'recovery', 'approval', 'handoff']) || !keysAre(s.policy, POLICY_KEYS)) return null;
  const p = s.policy;
  if (p.version !== 1 || p.authorized_uid !== 1002 || p.user_id !== USER_ID || p.session_key !== SESSION_KEY || p.max_messages !== 10 || !int(p.issued_unix) || !int(p.expires_unix) || p.expires_unix - p.issued_unix !== 72 * 60 * 60 || ['project_creation', 'personal_content', 'arbitrary_code', 'work_mode'].some(k => p[k] !== false) || !int(now) || now < p.issued_unix || now >= p.expires_unix) return null;
  if (!keysAre(s.journal, JOURNAL_KEYS)) return null;
  const j = s.journal;
  if (j.version !== 1 || j.paused !== false || !UUID.test(j.tab_id) || !Array.isArray(j.operations) || j.operations.length !== 1 || !keysAre(j.operations[0], OP_KEYS)) return null;
  const op = j.operations[0];
  if (op.operation_id !== OPERATION_ID || op.test !== 'ping' || op.phase !== 'mutation_started' || typeof op.nonce !== 'string' || !NONCE.test(op.nonce) || j.thread_id !== null) return null;
  if (!keysAre(s.guard, GUARD_KEYS)) return null;
  const g = s.guard;
  if (g.version !== 2 || g.operationId !== OPERATION_ID || g.nonce !== op.nonce || !keysAre(g.enrollment, ENROLLMENT_KEYS) || g.enrollment.userId !== USER_ID || !Array.isArray(g.enrollment.tabIds) || g.enrollment.tabIds.length !== 1 || !UUID.test(g.enrollment.tabIds[0])) return null;
  if (!keysAre(s.handoff, HANDOFF_KEYS)) return null;
  const h = s.handoff;
  if (h.version !== 1 || h.operation_id !== OPERATION_ID || h.nonce !== op.nonce || !UUID.test(h.original_tab_id) || !UUID.test(h.replacement_tab_id) || h.original_tab_id === h.replacement_tab_id || h.thread_id !== THREAD_ID || h.phase !== 'pending' || h.original_tab_id !== j.tab_id || ![h.original_tab_id, h.replacement_tab_id].includes(g.enrollment.tabIds[0])) return null;
  if (!keysAre(s.recovery, RECOVERY_KEYS)) return null;
  const r = s.recovery;
  if (r.version !== 1 || r.operationId !== OPERATION_ID || r.userId !== USER_ID || r.sessionKey !== SESSION_KEY || r.originalTabId !== h.original_tab_id || r.threadId !== THREAD_ID || r.url !== URL || r.nonce !== op.nonce || r.phase !== 'verified' || r.tabId !== h.replacement_tab_id) return null;
  if (!keysAre(s.approval, APPROVAL_KEYS)) return null;
  const a = s.approval;
  if (a.version !== 1 || a.operation_id !== OPERATION_ID || a.original_tab_id !== h.original_tab_id || a.replacement_tab_id !== h.replacement_tab_id || a.thread_id !== THREAD_ID || a.user_id !== USER_ID || a.session_key !== SESSION_KEY || a.observe_only !== true || !int(a.issued_unix) || !int(a.expires_unix) || a.issued_unix < p.issued_unix || a.issued_unix > now || now >= a.expires_unix || a.expires_unix > p.expires_unix) return null;
  if (j.tab_id !== h.original_tab_id || j.thread_id !== null || ![h.original_tab_id, h.replacement_tab_id].includes(g.enrollment.tabIds[0])) return null;
  return {operationId: OPERATION_ID, userId: USER_ID, threadId: THREAD_ID, url: URL, tabId: h.replacement_tab_id};
}

/** Construct a pure, injected, fail-closed callback for lease_guard. */
export function createPendingHandoffAuthorizer({loadSnapshot, now, verifyReadOnly}) {
  if (typeof loadSnapshot !== 'function' || typeof now !== 'function' || typeof verifyReadOnly !== 'function') throw Error('handoff_authorizer_dependencies_invalid');
  return async function authorizeHandoff(request) {
    try {
      if (!keysAre(request, ['operationId', 'nonce', 'originalTabId', 'replacementTabId']) || request.operationId !== OPERATION_ID || typeof request.nonce !== 'string' || !NONCE.test(request.nonce) || !UUID.test(request.originalTabId) || !UUID.test(request.replacementTabId) || request.originalTabId === request.replacementTabId) return false;
      const time1 = now();
      if (!int(time1)) return false;
      const loaded = loadSnapshot();
      if (loaded && typeof loaded.then === 'function') return false;
      const before = structuredClone(loaded);
      if (!validate(before, request, time1)) return false;
      const h = before.handoff;
      if (request.nonce !== before.journal.operations[0].nonce || request.originalTabId !== h.original_tab_id || request.replacementTabId !== h.replacement_tab_id) return false;
      const trustedArgs = Object.freeze({operationId: OPERATION_ID, userId: USER_ID, threadId: THREAD_ID, url: URL, tabId: h.replacement_tab_id});
      if (await verifyReadOnly(trustedArgs) !== true) return false;
      const after = loadSnapshot();
      if (after && typeof after.then === 'function') return false;
      const time2 = now();
      if (!int(time2) || time2 < time1 || !validate(before, request, time2)) return false;
      const identity2 = validate(after, request, time2);
      if (!identity2 || request.nonce !== after.journal.operations[0].nonce || request.originalTabId !== after.handoff.original_tab_id || request.replacementTabId !== after.handoff.replacement_tab_id) return false;
      return JSON.stringify(before) === JSON.stringify(after);
    } catch { return false; }
  };
}
