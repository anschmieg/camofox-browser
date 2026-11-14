/**
 * Narrow injected Camofox recovery adapter. The caller must persist the controller's
 * intent before invoking createReplacement; this module is not a durable journal and
 * must never be used to replay an uncertain page creation.
 */
import {RECOVERY_IDENTITY} from './pending_recovery.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CREATE_KEYS = ['userId', 'sessionKey', 'originalTabId', 'threadId', 'url'];
const VERIFY_KEYS = ['userId', 'tabId', 'threadId', 'url', 'operationId'];
const DIAGNOSTIC_PROMPT = 'Synthetic sandbox diagnostic sandbox-ping-20261014-062904. Reply with exactly SANDBOX_OK.';
const fail = code => { throw Error(code); };
const exactKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
function countTabs(sessions, sessionKey) {
  let global = 0, session = 0;
  for (const [key, entry] of sessions) {
    if (!(entry?.tabGroups instanceof Map)) fail('recovery_browser_group_unavailable');
    for (const group of entry.tabGroups.values()) {
      if (!(group instanceof Map)) fail('recovery_browser_group_unavailable');
      global += group.size;
      if (key === sessionKey) session += group.size;
    }
  }
  return {session, global};
}

export function createPendingRecoveryBrowser({sessions, normalizeUserId, createTabState, makeTabId,
  maxTabsPerSession, maxTabsGlobal, getTotalTabCount, verifyReadOnly, restoreDedicatedSession}) {
  if (!(sessions instanceof Map) || typeof normalizeUserId !== 'function' || typeof createTabState !== 'function' ||
      typeof makeTabId !== 'function' || !Number.isSafeInteger(maxTabsPerSession) || maxTabsPerSession < 1 ||
      !Number.isSafeInteger(maxTabsGlobal) || maxTabsGlobal < 1 || typeof getTotalTabCount !== 'function' ||
      typeof verifyReadOnly !== 'function' || restoreDedicatedSession !== undefined && typeof restoreDedicatedSession !== 'function')
    throw Error('recovery_browser_dependencies_invalid');

  async function createReplacement(args, authorizationGate) {
    const gate = () => { if (typeof authorizationGate !== 'function' || authorizationGate() !== true) fail('recovery_browser_authority_required'); };
    if (!exactKeys(args, CREATE_KEYS) || args.userId !== RECOVERY_IDENTITY.userId ||
        args.sessionKey !== RECOVERY_IDENTITY.sessionKey || args.threadId !== RECOVERY_IDENTITY.threadId ||
        args.url !== RECOVERY_IDENTITY.url || typeof args.originalTabId !== 'string' || !UUID.test(args.originalTabId))
      fail('recovery_browser_scope_invalid');
    const userKey = normalizeUserId(args.userId);
    const sessionKey = normalizeUserId(RECOVERY_IDENTITY.userId);
    if (userKey !== RECOVERY_IDENTITY.userId || sessionKey !== userKey) fail('recovery_browser_user_scope_invalid');
    let session = sessions.get(userKey);
    const coldRestore = !sessions.has(userKey) && restoreDedicatedSession !== undefined;
    if (coldRestore) {
      gate();
      session = await restoreDedicatedSession(Object.freeze({userId: RECOVERY_IDENTITY.userId,
        sessionKey: RECOVERY_IDENTITY.sessionKey}));
      if (sessions.get(userKey) !== session) fail('recovery_browser_session_unavailable');
    }
    if (!session || session._closing || !session.context || typeof session.context.newPage !== 'function')
      fail('recovery_browser_session_unavailable');
    const context = session.context;
    const groups = session.tabGroups;
    if (!(groups instanceof Map)) fail('recovery_browser_group_unavailable');
    let group = groups.get(RECOVERY_IDENTITY.sessionKey);
    if (coldRestore && group === undefined) {
      group = new Map();
      groups.set(RECOVERY_IDENTITY.sessionKey, group);
    }
    if (!(group instanceof Map)) fail('recovery_browser_group_unavailable');
    const counts = countTabs(sessions, userKey);
    const physicalGlobal = getTotalTabCount();
    if (!Number.isSafeInteger(physicalGlobal) || physicalGlobal < 0) fail('recovery_browser_capacity_unavailable');
    if (counts.session >= maxTabsPerSession || Math.max(counts.global, physicalGlobal) >= maxTabsGlobal)
      fail('recovery_browser_capacity');
    for (const candidate of groups.values()) {
      if (!(candidate instanceof Map)) fail('recovery_browser_group_unavailable');
      if (candidate.has(args.originalTabId)) fail('recovery_browser_original_tab_present');
    }

    gate();
    const page = await context.newPage(); // exactly once; never retry this irreversible operation
    if (sessions.get(userKey) !== session || session._closing || session.context !== context || session.tabGroups !== groups || groups.get(RECOVERY_IDENTITY.sessionKey) !== group)
      fail('recovery_browser_session_changed');
    const tabId = makeTabId();
    if (typeof tabId !== 'string' || !UUID.test(tabId) || tabId === args.originalTabId || group.has(tabId))
      fail('recovery_browser_tab_id_invalid');
    const state = createTabState(page);
    if (!state || state.page !== page) fail('recovery_browser_tab_state_invalid');
    if (state.visitedUrls instanceof Set) state.visitedUrls.add(args.url);
    state.lastRequestedUrl = args.url;
    group.set(tabId, state); // retain an irreversible page in managed state before navigation
    gate();
    await page.goto(args.url, {waitUntil: 'domcontentloaded', timeout: 30000});
    if (sessions.get(userKey) !== session || session._closing || session.context !== context || session.tabGroups !== groups || groups.get(RECOVERY_IDENTITY.sessionKey) !== group || group.get(tabId) !== state)
      fail('recovery_browser_session_changed');
    if (page.url() !== args.url) fail('recovery_browser_redirect_refused');
    return Object.freeze({tabId});
  }

  async function verifyReplacement(args) {
    if (!exactKeys(args, VERIFY_KEYS) || args.userId !== RECOVERY_IDENTITY.userId ||
        args.operationId !== RECOVERY_IDENTITY.operationId || args.threadId !== RECOVERY_IDENTITY.threadId ||
        args.url !== RECOVERY_IDENTITY.url || typeof args.tabId !== 'string' || !UUID.test(args.tabId)) return false;
    const userKey = normalizeUserId(args.userId);
    if (userKey !== RECOVERY_IDENTITY.userId || normalizeUserId(RECOVERY_IDENTITY.userId) !== userKey) return false;
    const session = sessions.get(userKey);
    if (!session || session._closing || !(session.tabGroups instanceof Map)) return false;
    const context = session.context, groups = session.tabGroups;
    const group = groups.get(RECOVERY_IDENTITY.sessionKey);
    const state = group?.get(args.tabId);
    if (!(group instanceof Map) || !state?.page || typeof state.page.url !== 'function') return false;
    let currentUrl;
    try { currentUrl = state.page.url(); } catch { return false; }
    if (currentUrl !== RECOVERY_IDENTITY.url) return false;
    try {
      const valid = await verifyReadOnly(Object.freeze({...args, sessionKey: RECOVERY_IDENTITY.sessionKey,
        prompt: DIAGNOSTIC_PROMPT, page: state.page})) === true;
      return valid && sessions.get(userKey) === session && !session._closing && session.context === context &&
        session.tabGroups === groups && groups.get(RECOVERY_IDENTITY.sessionKey) === group && group.get(args.tabId) === state &&
        state.page.url() === RECOVERY_IDENTITY.url;
    } catch { return false; }
  }

  return Object.freeze({createReplacement, verifyReplacement});
}
