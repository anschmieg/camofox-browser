/**
 * Offline-only recovery state machine. Injected adapters must be local, synchronous
 * durable storage and narrowly scoped browser operations. The nonce is retained in
 * the private recovery journal solely to bind it to the v2 reservation across restart;
 * it is never returned or sent to createReplacement/verifyReplacement.
 */
export const RECOVERY_IDENTITY = Object.freeze({
  operationId: 'sandbox-ping-20261014-062904',
  userId: 'chatgpt_api_747f523e17a267049e019e26',
  sessionKey: 'chatgpt_api_acceptance',
  threadId: '6acf2151-2e8c-83ed-9b7e-64f8bb0887a9',
  url: 'https://chatgpt.com/c/6acf2151-2e8c-83ed-9b7e-64f8bb0887a9',
});

const VERSION = 1;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE = /^[0-9a-f]{64}$/;
const phases = new Set(['intent', 'created', 'verified']);
const fail = code => Object.freeze({ok: false, status: code});

function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function reservationTabId(r, operationId, nonce) {
  if (!exactKeys(r, ['version', 'operationId', 'nonce', 'enrollment']) ||
      r.version !== 2 || r.operationId !== operationId || r.nonce !== nonce ||
      !exactKeys(r.enrollment, ['userId', 'tabIds']) || r.enrollment.userId !== RECOVERY_IDENTITY.userId ||
      !Array.isArray(r.enrollment.tabIds) || r.enrollment.tabIds.length !== 1 ||
      typeof r.enrollment.tabIds[0] !== 'string' || !UUID.test(r.enrollment.tabIds[0])) return null;
  return r.enrollment.tabIds[0];
}
function validJournal(j) {
  const base = ['version', 'operationId', 'userId', 'sessionKey', 'originalTabId', 'threadId', 'url', 'nonce', 'phase'];
  if (!j || !phases.has(j.phase)) return false;
  const keys = j.phase === 'intent' ? base : [...base, 'tabId'];
  return exactKeys(j, keys) && j.version === VERSION &&
    j.operationId === RECOVERY_IDENTITY.operationId && j.userId === RECOVERY_IDENTITY.userId &&
    j.sessionKey === RECOVERY_IDENTITY.sessionKey && typeof j.originalTabId === 'string' && UUID.test(j.originalTabId) &&
    j.threadId === RECOVERY_IDENTITY.threadId && j.url === RECOVERY_IDENTITY.url && NONCE.test(j.nonce) &&
    (j.phase === 'intent' || typeof j.tabId === 'string' && UUID.test(j.tabId) && j.tabId !== j.originalTabId);
}
function publicResult(j) {
  return Object.freeze({ok: true, status: j.phase, ...(j.tabId ? {tabId: j.tabId} : {}),
    ...(j.phase === 'verified' ? {plan: Object.freeze({userId: RECOVERY_IDENTITY.userId,
      tabId: j.tabId, threadId: RECOVERY_IDENTITY.threadId, url: RECOVERY_IDENTITY.url})} : {})});
}

export function createPendingRecovery({store, getReservation, createReplacement, verifyReplacement, authorizeRecovery}) {
  if (!store || typeof store.load !== 'function' || typeof store.save !== 'function' ||
      typeof getReservation !== 'function' || typeof createReplacement !== 'function' ||
      typeof verifyReplacement !== 'function' || (authorizeRecovery !== undefined && typeof authorizeRecovery !== 'function')) throw Error('recovery_dependencies_invalid');
  const authorize = authorizeRecovery || (() => false);
  let busy = false;
  let poisoned = false;
  let cache;
  try { cache = store.load(); } catch { poisoned = true; }
  if (cache !== null && cache !== undefined && !validJournal(cache)) poisoned = true;

  function persist(next) {
    try { store.save(next); cache = next; }
    catch { poisoned = true; throw Error('recovery_storage_unavailable'); }
  }
  function currentOwnerTab(op, nonce) {
    let reservation;
    try { reservation = getReservation(); } catch { return null; }
    return reservationTabId(reservation, op, nonce);
  }
  const authorizationScope = {active: false, intent: null, ownerTabId: null};
  function authorizationGate() {
    if (!authorizationScope.active) return false;
    let allowed = false;
    try { allowed = authorize(Object.freeze({operationId: authorizationScope.intent.operationId,
      nonce: authorizationScope.intent.nonce, originalTabId: authorizationScope.ownerTabId, stage: 'continue_create'})); } catch { allowed = false; }
    if (allowed && typeof allowed.then === 'function' || allowed !== true) return false;
    return currentOwnerTab(authorizationScope.intent.operationId, authorizationScope.intent.nonce) === authorizationScope.ownerTabId;
  }
  async function authorizeStage(stage, journal, ownerTabId) {
    let allowed = false;
    try { allowed = await authorize(Object.freeze({operationId: journal.operationId, nonce: journal.nonce,
      originalTabId: ownerTabId, stage})); } catch { allowed = false; }
    if (allowed !== true) return 'recovery_authority_required';
    return currentOwnerTab(journal.operationId, journal.nonce) === ownerTabId ? null : 'recovery_owner_mismatch';
  }
  async function observe(journal) {
    const authorizationFailure = await authorizeStage('observe', journal, journal.originalTabId);
    if (authorizationFailure) return fail(authorizationFailure);
    let valid = false;
    try {
      valid = await verifyReplacement(Object.freeze({userId: RECOVERY_IDENTITY.userId,
        tabId: journal.tabId, threadId: RECOVERY_IDENTITY.threadId, url: RECOVERY_IDENTITY.url,
        operationId: RECOVERY_IDENTITY.operationId}));
    } catch { valid = false; }
    const finalAuthorizationFailure = await authorizeStage('observe', journal, journal.originalTabId);
    if (finalAuthorizationFailure) return fail(finalAuthorizationFailure);
    if (valid !== true) return fail('recovery_pending');
    if (journal.phase !== 'verified') {
      const verified = {...journal, phase: 'verified'};
      try { persist(verified); } catch { return fail('recovery_storage_unavailable'); }
      journal = verified;
    }
    return publicResult(journal);
  }
  return Object.freeze({
    async recover(request) {
      if (busy) return fail('recovery_busy');
      busy = true;
      try {
        if (poisoned) return fail('recovery_storage_unavailable');
        if (!exactKeys(request, ['operationId', 'nonce']) || request.operationId !== RECOVERY_IDENTITY.operationId ||
            typeof request.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(request.nonce)) return fail('recovery_request_invalid');
        const identity = Object.freeze({operationId: request.operationId, nonce: request.nonce});
        const ownerTabId = currentOwnerTab(identity.operationId, identity.nonce);
        if (!ownerTabId) return fail('recovery_owner_mismatch');
        if (cache) {
          if (!validJournal(cache)) { poisoned = true; return fail('recovery_journal_invalid'); }
          if (cache.operationId !== identity.operationId || cache.nonce !== identity.nonce || cache.originalTabId !== ownerTabId) return fail('recovery_owner_mismatch');
          if (cache.phase === 'intent') return fail('recovery_creation_uncertain');
          return await observe(cache);
        }
        const intent = {version: VERSION, operationId: RECOVERY_IDENTITY.operationId,
          userId: RECOVERY_IDENTITY.userId, sessionKey: RECOVERY_IDENTITY.sessionKey,
          originalTabId: ownerTabId, threadId: RECOVERY_IDENTITY.threadId, url: RECOVERY_IDENTITY.url,
          nonce: identity.nonce, phase: 'intent'};
        const authorizationFailure = await authorizeStage('create', intent, ownerTabId);
        if (authorizationFailure) return fail(authorizationFailure);
        try { persist(intent); } catch { return fail('recovery_storage_unavailable'); }
        authorizationScope.active=true;authorizationScope.intent=intent;authorizationScope.ownerTabId=ownerTabId;
        let created;
        try {
          created = await createReplacement(Object.freeze({userId: RECOVERY_IDENTITY.userId,
            sessionKey: RECOVERY_IDENTITY.sessionKey, originalTabId: ownerTabId,
            threadId: RECOVERY_IDENTITY.threadId, url: RECOVERY_IDENTITY.url}), authorizationGate);
        } catch { return fail('recovery_creation_uncertain'); }
        finally { authorizationScope.active=false;authorizationScope.intent=null;authorizationScope.ownerTabId=null; }
        if (!exactKeys(created, ['tabId'])) return fail('recovery_creation_uncertain');
        const tabId = created.tabId;
        if (typeof tabId !== 'string' || !UUID.test(tabId) || tabId === ownerTabId) return fail('recovery_creation_uncertain');
        const createdJournal = {...intent, phase: 'created', tabId};
        try { persist(createdJournal); } catch { return fail('recovery_storage_unavailable'); }
        if (currentOwnerTab(identity.operationId, identity.nonce) !== ownerTabId) return fail('recovery_owner_mismatch');
        return await observe(createdJournal);
      } finally { busy = false; }
    },
  });
}
