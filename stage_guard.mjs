/** Pure source transformer. Never edits the installed server or starts it. */
import {createHash} from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
export const SOURCE_SHA256='903c10876634f747b1498b3c0539f63dac55b6e807fa4a45fb5517b9a668e8c4';
export const PERSISTENCE_PLUGIN_SHA256='105f8e54ec5e18f4e7803914543b4ef14e7112e7f4be8566f4f000962cf81c6a';
const hash=x=>createHash('sha256').update(x).digest('hex');
const MAX_PINNED_SOURCE_BYTES=1_000_000;
export function readRegularBounded(filePath,maxBytes=MAX_PINNED_SOURCE_BYTES){
  let fd;
  try{
    const absolute=path.resolve(filePath);
    const parsed=path.parse(absolute);
    let current=parsed.root;
    for(const component of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)){
      current=path.join(current,component);
      const componentStat=fs.lstatSync(current);
      if(componentStat.isSymbolicLink())throw Error('persistence_source_symlink_rejected');
      if(current!==absolute&&!componentStat.isDirectory())throw Error('persistence_source_parent_invalid');
    }
    fd=fs.openSync(absolute,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
    const stat=fs.fstatSync(fd);
    if(!stat.isFile()||stat.size>maxBytes)throw Error('persistence_source_file_invalid');
    const data=fs.readFileSync(fd);
    if(data.length>maxBytes)throw Error('persistence_source_file_too_large');
    return data;
  }finally{if(fd!==undefined)fs.closeSync(fd);}
}
const RECOVERY_USER='chatgpt_api_747f523e17a267049e019e26';
const RECOVERY_SESSION='chatgpt_api_acceptance';
const PERSISTENCE_CLOSURE_PINS={
  'plugins/persistence/index.js':PERSISTENCE_PLUGIN_SHA256,
  'lib/persistence.js':'d9f9431644aea772bb0b870a4cf8907d9e9909e399667635a4f33abdb797e328',
  'lib/cookies.js':'d20615d2ea4281fc43c94334f859496e3ee3758dbfb26e86ffeba9262b25bb13',
  'mcp/lib/cookies.mjs':'c8d593d416bf22e1961d1b806a572fa018c0791f2addf1d55cc0a3c66b14aa67'
};
const PERSISTENCE_LOADER_SHA256='72b8e6da7bc70ddb25c71154a2ac771ca3b49a36fe2b3c57944680ad12cfcf24';
const PERSISTENCE_PACKAGE_SHA256='2a9011d530dfb47ca1a18a1d78893686d8f630f820755a05da4ce2369dc1b258';
export function verifiedPersistenceClosure(pluginFile) {
  const root=path.resolve(path.dirname(pluginFile),'../..');
  const files={};
  for(const [relative,pinned] of Object.entries(PERSISTENCE_CLOSURE_PINS)){
    const absolute=path.resolve(root,relative);
    if(!absolute.startsWith(root+path.sep))throw Error('persistence_closure_path_invalid');
    const actual=hash(readRegularBounded(absolute));
    if(actual!==pinned)throw Error('persistence_closure_revision_mismatch');
    files[relative]=actual;
  }
  const loaderSha256=hash(readRegularBounded(path.join(root,'lib/plugins.js')));
  const packageSha256=hash(readRegularBounded(path.join(root,'package.json')));
  if(loaderSha256!==PERSISTENCE_LOADER_SHA256||packageSha256!==PERSISTENCE_PACKAGE_SHA256)throw Error('persistence_source_evidence_mismatch');
  const canonical=JSON.stringify(Object.fromEntries(Object.entries(files).sort()));
  return {files,sha256:hash(canonical),loaderSha256,packageSha256};
}
export function stagePersistencePlugin(source) {
  if(typeof source!=='string'||hash(source)!==PERSISTENCE_PLUGIN_SHA256)throw Error('persistence_plugin_revision_mismatch');
  const creating="  events.on('session:creating', async ({ userId, contextOptions }) => {\n    if (resettingUsers.has(userId)) return;\n    const storageStatePath = await loadPersistedStorageState(profileDir, userId, logger);\n    if (storageStatePath) {\n      contextOptions.storageState = storageStatePath;\n      log('info', 'restoring persisted storage state', { userId, storageStatePath });\n    }\n  });";
  const created="  events.on('session:created', async ({ userId, context }) => {\n    activeSessions.set(userId, context);\n\n    // If no persisted state was restored, try bootstrap cookies\n    const existingState = await loadPersistedStorageState(profileDir, userId, logger);\n    if (!existingState) {\n      const result = await importBootstrapCookies({\n        cookiesDir: config.cookiesDir,\n        context,\n        logger,\n      });\n      if (result.imported > 0) {\n        log('info', 'bootstrap cookies imported', { userId, count: result.imported, source: result.source });\n        await checkpoint(userId, context, 'bootstrap_cookies');\n      }\n    }\n  });";
  if(source.split(creating).length!==2||source.split(created).length!==2)throw Error('persistence_plugin_anchor_mismatch');
  const strictCreating=`  events.on('session:creating', async ({ userId, contextOptions, recoveryDescriptor }) => {
    if (recoveryDescriptor !== undefined) {
      if (!recoveryDescriptor || recoveryDescriptor.kind !== 'dedicated-persisted-state-v1' ||
          recoveryDescriptor.userId !== userId || userId !== 'chatgpt_api_747f523e17a267049e019e26' ||
          recoveryDescriptor.sessionKey !== 'chatgpt_api_acceptance' || resettingUsers.has(userId) || !profileDir)
        throw new Error('recovery_persisted_state_scope_invalid');
      const { storageStatePath, metaPath } = getUserPersistencePaths(profileDir, userId);
      const [raw, metaRaw] = await Promise.all([fs.readFile(storageStatePath, 'utf8'), fs.readFile(metaPath, 'utf8')]);
      const state = JSON.parse(raw);
      const meta = JSON.parse(metaRaw);
      if (!state || typeof state !== 'object' || !Array.isArray(state.cookies) ||
          (state.origins !== undefined && !Array.isArray(state.origins)) ||
          !meta || meta.userId !== userId || meta.storageStatePath !== storageStatePath)
        throw new Error('recovery_persisted_state_invalid');
      contextOptions.storageState = state;
      const freezeTree = value => { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freezeTree(child); Object.freeze(value); } return value; };
      freezeTree(state);
      Object.defineProperties(recoveryDescriptor, {
        state:{value:state, enumerable:true},
        storageStatePath:{value:storageStatePath, enumerable:true},
        stateSha256:{value:crypto.createHash('sha256').update(JSON.stringify(state)).digest('hex'), enumerable:true},
        acknowledged:{value:true, enumerable:true}
      });
      return;
    }
    if (resettingUsers.has(userId)) return;
    const storageStatePath = await loadPersistedStorageState(profileDir, userId, logger);
    if (storageStatePath) {
      contextOptions.storageState = storageStatePath;
      log('info', 'restoring persisted storage state', { userId, storageStatePath });
    }
  });`;
  const strictCreated=`  events.on('session:created', async ({ userId, context, recoveryDescriptor }) => {
    activeSessions.set(userId, context);
    if (recoveryDescriptor !== undefined) {
      if (!recoveryDescriptor.acknowledged || recoveryDescriptor.userId !== userId ||
          recoveryDescriptor.kind !== 'dedicated-persisted-state-v1') throw new Error('recovery_persisted_state_acknowledgment_invalid');
      return;
    }
    const existingState = await loadPersistedStorageState(profileDir, userId, logger);
    if (!existingState) {
      const result = await importBootstrapCookies({cookiesDir: config.cookiesDir, context, logger});
      if (result.imported > 0) {
        log('info', 'bootstrap cookies imported', { userId, count: result.imported, source: result.source });
        await checkpoint(userId, context, 'bootstrap_cookies');
      }
    }
  });`;
  return source.replace("import fs from 'node:fs/promises';","import fs from 'node:fs/promises';\nimport crypto from 'node:crypto';").replace(creating,strictCreating).replace(created,strictCreated);
}
export function stageGuard(source,modulePath,recoveryBundle) {
  if(hash(source)!==SOURCE_SHA256)throw Error('camofox_source_revision_mismatch');
  let recoverySource='';
  let handoffFiles;
  const creationFiles={policyFile:'/var/lib/chatgpt-sandbox-broker/policy.json',journalFile:'/var/lib/chatgpt-sandbox-broker/journal.json',creationApprovalFile:'/var/lib/chatgpt-sandbox-broker/recovery-creation-approval.json'};
  if(recoveryBundle!==undefined){
    const recoveryKeys=Object.keys(recoveryBundle||{}).sort().join(',');
    if(!recoveryBundle||typeof recoveryBundle!=='object'||Array.isArray(recoveryBundle)||
      !['domSha256,domSource','domSha256,domSource,restoreColdContext','domSha256,domSource,handoffFiles','domSha256,domSource,handoffFiles,restoreColdContext','domSha256,domSource,handoffFiles,persistenceClosureFiles,persistenceClosureSha256,persistenceLoaderSha256,persistencePackageSha256,persistencePluginSource,restoreColdContext','domSha256,domSource,persistenceClosureFiles,persistenceClosureSha256,persistenceLoaderSha256,persistencePackageSha256,persistencePluginSource,restoreColdContext'].includes(recoveryKeys)||
      Object.hasOwn(recoveryBundle,'restoreColdContext')&&recoveryBundle.restoreColdContext!==true||
      typeof recoveryBundle.domSource!=='string'||!recoveryBundle.domSource.length||recoveryBundle.domSource.length>100_000||typeof recoveryBundle.domSha256!=='string'||
      !/^[a-f0-9]{64}$/.test(recoveryBundle.domSha256)||hash(recoveryBundle.domSource)!==recoveryBundle.domSha256)
      throw Error('recovery_bundle_invalid');
    recoverySource=recoveryBundle.domSource;
    if(Object.hasOwn(recoveryBundle,'handoffFiles')){
      const files=recoveryBundle.handoffFiles;
      const expected={policyFile:'/var/lib/chatgpt-sandbox-broker/policy.json',journalFile:'/var/lib/chatgpt-sandbox-broker/journal.json',approvalFile:'/var/lib/chatgpt-sandbox-broker/recovery-approval.json',handoffFile:'/var/lib/chatgpt-sandbox-broker/pending-handoff.json'};
      if(!files||typeof files!=='object'||Array.isArray(files)||Object.keys(files).sort().join(',')!==Object.keys(expected).sort().join(',')||
        Object.keys(expected).some(key=>typeof files[key]!=='string'||!path.isAbsolute(files[key])||path.normalize(files[key])!==files[key]||files[key]!==expected[key])||
        new Set(Object.values(files)).size!==4)throw Error('handoff_files_invalid');
      handoffFiles=files;
    }
  }
  if(!path.isAbsolute(modulePath)||!/^\/[A-Za-z0-9_./-]+\/guard_bootstrap\.mjs$/.test(modulePath))throw Error('guard_absolute_module_required');
  const anchor='app.use(accessKeyMiddleware(CONFIG));';
  const fly="app.use('/tabs/:tabId', fly.replayMiddleware(log));";
  if(source.split(anchor).length!==2||source.split(fly).length!==2)throw Error('camofox_source_anchor_mismatch');
  const addition=recoveryBundle===undefined?`\n// Paperclip guard candidate: explicit activation/config required.\nif (!CONFIG.accessKey) throw new Error('Camofox access key required for Paperclip guard');\nconst { loadGuard } = await import(${JSON.stringify(modulePath)});\nconst paperclipGuard = loadGuard(process.env.PAPERCLIP_CAMOFOX_GUARD_CONFIG);\n// The upstream global parser deliberately skips evaluate; parse it before the guard.\napp.use('/tabs/:tabId/evaluate', express.json({limit:'100kb'}));\napp.use(paperclipGuard.middleware);\n${fly}\n`:`\n// Paperclip guard candidate: explicit activation/config required.\nif (!CONFIG.accessKey) throw new Error('Camofox access key required for Paperclip guard');\nlet paperclipGuard;\n// The upstream global parser deliberately skips evaluate; parse it before the guard.\napp.use('/tabs/:tabId/evaluate', express.json({limit:'100kb'}));\n// Requests can only arrive after initialization and server.listen.\napp.use((req, res, next) => paperclipGuard ? paperclipGuard.middleware(req, res, next) : res.status(503).json({ok:false,error:'guard_initializing'}));\n${fly}\n`;
  const runtimeAnchor='const MAX_TABS_GLOBAL = CONFIG.maxTabsGlobal;';
  const runtimeEndAnchor='const HANDLER_TIMEOUT_MS = CONFIG.handlerTimeoutMs;';
  const sessionSignature='async function getSession(userId, { trace = false } = {}) {';
  const creatingPayload="await pluginEvents.emitAsync('session:creating', { userId: key, contextOptions });";
  const contextCreate='      const context = await b.newContext(contextOptions);';
  const createdPayload="await pluginEvents.emitAsync('session:created', { userId: key, context });";
  const newSessionSignature='async function getSession(userId, { trace = false } = {}) {';
  const pluginCreatingAnchor="  events.on('session:creating', async ({ userId, contextOptions }) => {\n    if (resettingUsers.has(userId)) return;\n    const storageStatePath = await loadPersistedStorageState(profileDir, userId, logger);\n    if (storageStatePath) {\n      contextOptions.storageState = storageStatePath;\n      log('info', 'restoring persisted storage state', { userId, storageStatePath });\n    }\n  });";
  const pluginCreatedAnchor="  events.on('session:created', async ({ userId, context }) => {\n    activeSessions.set(userId, context);\n\n    // If no persisted state was restored, try bootstrap cookies\n    const existingState = await loadPersistedStorageState(profileDir, userId, logger);\n    if (!existingState) {\n      const result = await importBootstrapCookies({\n        cookiesDir: config.cookiesDir,\n        context,\n        logger,\n      });\n      if (result.imported > 0) {\n        log('info', 'bootstrap cookies imported', { userId, count: result.imported, source: result.source });\n        await checkpoint(userId, context, 'bootstrap_cookies');\n      }\n    }\n  });";
  const recoveryServerSource=recoveryBundle?.restoreColdContext===true?source.replace(newSessionSignature,'async function getSession(userId, { trace = false, recoveryDescriptor } = {}) {').replace(creatingPayload,"await pluginEvents.emitAsync('session:creating', { userId: key, contextOptions, recoveryDescriptor });\n      if (recoveryDescriptor) {\n        if (!recoveryDescriptor.acknowledged || recoveryDescriptor.userId !== key || recoveryDescriptor.sessionKey !== 'chatgpt_api_acceptance' || recoveryDescriptor.kind !== 'dedicated-persisted-state-v1') throw new Error('recovery_persistence_not_acknowledged');\n        const expectedState = recoveryDescriptor.state;\n        const expectedPath = recoveryDescriptor.storageStatePath;\n        if (!expectedState || contextOptions.storageState !== expectedState) throw new Error('recovery_persistence_state_missing');\n        if (!expectedPath || !Array.isArray(expectedState.cookies) || (expectedState.origins !== undefined && !Array.isArray(expectedState.origins)) || crypto.createHash('sha256').update(JSON.stringify(expectedState)).digest('hex') !== recoveryDescriptor.stateSha256) throw new Error('recovery_persistence_state_invalid');\n      }").replace(contextCreate,"      if (recoveryDescriptor && contextOptions.storageState !== recoveryDescriptor.state) throw new Error('recovery_persistence_options_tampered');\n      const context = await b.newContext(contextOptions);").replace(createdPayload,"await pluginEvents.emitAsync('session:created', { userId: key, context, recoveryDescriptor });\n      if (recoveryDescriptor) {\n        Object.defineProperty(created, '_recoveryDescriptor', {value:recoveryDescriptor, enumerable:false});\n      }"):'source';
  const restoreColdContext=recoveryBundle?.restoreColdContext===true?`
  restoreDedicatedSession: async (args) => {
    if (!args || Object.keys(args).sort().join(',') !== 'sessionKey,userId' ||
        args.userId !== ${JSON.stringify(RECOVERY_USER)} || args.sessionKey !== ${JSON.stringify(RECOVERY_SESSION)})
      throw new Error('recovery_cold_context_scope_invalid');
    const userId = ${JSON.stringify(RECOVERY_USER)};
    if (sessions.has(userId) || sessionCreations.has(userId)) throw new Error('recovery_cold_context_not_cold');
    const recoveryDescriptor = {kind:'dedicated-persisted-state-v1', userId, sessionKey:${JSON.stringify(RECOVERY_SESSION)}, acknowledged:false, state:undefined};
    const session = await getSession(userId, {trace:false, recoveryDescriptor});
    if (sessions.get(userId) !== session || session._closing) throw new Error('recovery_cold_context_session_unavailable');
    if (session._recoveryDescriptor !== recoveryDescriptor) throw new Error('recovery_cold_context_descriptor_mismatch');
    return session;
  },` : '';
  const runtimeInit=recoveryBundle===undefined?'':`
// Initialize only after sessions and tab limits are declared; no request runs before listen.
const {loadGuard} = await import(${JSON.stringify(modulePath)});
const {${handoffFiles?'createHandoffStateReader, ':''}createRecoveryCreationStateReader} = await import(${JSON.stringify(path.join(path.dirname(modulePath),'handoff_state_reader.mjs'))});
paperclipGuard = loadGuard(process.env.PAPERCLIP_CAMOFOX_GUARD_CONFIG, {
  enabled: true, sessions, normalizeUserId, createTabState, makeTabId: fly.makeTabId,
  maxTabsPerSession: MAX_TABS_PER_SESSION, maxTabsGlobal: MAX_TABS_GLOBAL, getTotalTabCount,
  domSource: ${JSON.stringify(recoverySource)}, domSha256: ${JSON.stringify(recoveryBundle?.domSha256)},${restoreColdContext}
  loadCreationState: createRecoveryCreationStateReader(${JSON.stringify(creationFiles)}),
  now: () => Math.floor(Date.now() / 1000)
}${handoffFiles?`, {enabled:true,loadBrokerState:createHandoffStateReader(${JSON.stringify(handoffFiles)}),now:()=>Math.floor(Date.now()/1000)}`:''});
`;
  if(recoveryBundle!==undefined&&(source.split(runtimeAnchor).length!==2||source.split(runtimeEndAnchor).length!==2||source.indexOf(runtimeAnchor)>source.indexOf(runtimeEndAnchor)))throw Error('camofox_recovery_runtime_anchor_mismatch');
  if(recoveryBundle?.restoreColdContext===true){
    if(source.split(sessionSignature).length!==2||source.split(creatingPayload).length!==2||source.split(contextCreate).length!==2||source.split(createdPayload).length!==2)throw Error('camofox_cold_recovery_hook_anchor_mismatch');
    if(typeof recoveryBundle.persistencePluginSource!=='string'||hash(recoveryBundle.persistencePluginSource)!==PERSISTENCE_PLUGIN_SHA256)throw Error('persistence_plugin_revision_mismatch');
    if(recoveryBundle.persistencePluginSource.split(pluginCreatingAnchor).length!==2||recoveryBundle.persistencePluginSource.split(pluginCreatedAnchor).length!==2)throw Error('persistence_plugin_anchor_mismatch');
    const expectedClosure={
      'plugins/persistence/index.js':PERSISTENCE_PLUGIN_SHA256,
      'lib/persistence.js':'d9f9431644aea772bb0b870a4cf8907d9e9909e399667635a4f33abdb797e328',
      'lib/cookies.js':'d20615d2ea4281fc43c94334f859496e3ee3758dbfb26e86ffeba9262b25bb13',
      'mcp/lib/cookies.mjs':'c8d593d416bf22e1961d1b806a572fa018c0791f2addf1d55cc0a3c66b14aa67'
    };
    if(!recoveryBundle.persistenceClosureFiles||JSON.stringify(Object.fromEntries(Object.entries(recoveryBundle.persistenceClosureFiles).sort()))!==JSON.stringify(Object.fromEntries(Object.entries(expectedClosure).sort()))||hash(JSON.stringify(Object.fromEntries(Object.entries(expectedClosure).sort())))!==recoveryBundle.persistenceClosureSha256||recoveryBundle.persistenceLoaderSha256!=='72b8e6da7bc70ddb25c71154a2ac771ca3b49a36fe2b3c57944680ad12cfcf24'||recoveryBundle.persistencePackageSha256!=='2a9011d530dfb47ca1a18a1d78893686d8f630f820755a05da4ce2369dc1b258')throw Error('persistence_closure_invalid');
  }
  const destroyTab='function destroyTab(session, tabId, reason, userId) {\n  const lock = tabLocks.get(tabId);';
  const destroySession="async function destroySession(userId, { reason = 'destroy_session' } = {}) {\n  const key = normalizeUserId(userId);";
  const shutdown='  await closeBrowserFully(`shutdown:${signal}`);\n  await sentryFlush(2000);\n  process.exit(0);';
  const closeOptions='async function closeSession(userId, session, {\n  reason = \'session_closed\',\n  clearDownloads = true,\n  clearLocks = true,\n} = {}) {';
  const closeCall='  await session.context.close().catch(() => {});';
  const reaperStart='// Per-tab inactivity reaper — close tabs idle for TAB_INACTIVITY_MS\nsetInterval(() => {';
  const pageClose='            safePageClose(tabState.page);\n            group.delete(tabId);';
  const reaperEnd='  if (sessions.size === 0) scheduleBrowserIdleShutdown();\n}, 60_000);\n\n// Orphan page reaper';
  const reaperSessionClose="      closeSession(userId, session, { reason: 'tab_reaper_empty_session', clearDownloads: true, clearLocks: true }).catch(() => {});";
  const staleStart='// Cleanup stale sessions\nsetInterval(() => {';
  const staleClose="      closeSession(userId, session, { reason: 'session_timeout', clearDownloads: true, clearLocks: true }).catch(() => {});";
  const staleEnd='  refreshTabLockQueueDepth();\n}, 60_000);\n\n// Memory pressure eviction';
  const orphanStart='// Orphan page reaper -- force-closes Playwright pages that survived a safePageClose\n// timeout or were otherwise dropped from tabGroups tracking. Without this, leaked\n// pages starve Firefox of DOM threads and eventually block new tab creation.\nsetInterval(() => {';
  const orphanClose='        page.close({ runBeforeUnload: false }).catch(() => {});';
  const orphanEnd="  if (reaped > 0) log('warn', 'orphan page reaper closed leaked pages', { reaped });\n}, 60_000);";
  const pressureStart='// Memory pressure eviction (Fly.io only) — evict oldest session when RAM is high.\n// Prevents Camoufox OOM by proactively freeing BrowserContexts.\nif (FLY_MACHINE_ID) {\n  const MEMORY_HIGH_WATERMARK = 0.80;\n  setInterval(() => {';
  const pressureClose="      closeSession(oldestKey, session, {\n        reason: 'memory_pressure', clearDownloads: true, clearLocks: true,\n      }).catch(() => {});";
  const pressureEnd='      usedRatio = 1 - (freeMem / totalMem);\n    }\n  }, 30_000);\n}';
  const idleShutdownStart='function scheduleBrowserIdleShutdown() {\n  if (browserIdleTimer || sessions.size > 0 || !browser) return;\n  browserIdleTimer = setTimeout(async () => {\n    browserIdleTimer = null;\n    if (sessions.size === 0 && browser) {\n      log(\'info\', \'browser idle shutdown (no sessions)\');\n      await closeBrowserFully(\'idle_shutdown\');\n    }\n  }, BROWSER_IDLE_TIMEOUT_MS);\n}';
  for (const [anchorText, errorCode] of [[idleShutdownStart,'camofox_idle_shutdown_anchor_mismatch'],[destroyTab,'camofox_destroy_tab_anchor_mismatch'],[destroySession,'camofox_destroy_session_anchor_mismatch'],[shutdown,'camofox_shutdown_anchor_mismatch'],[closeOptions,'camofox_close_session_anchor_mismatch'],[closeCall,'camofox_context_close_anchor_mismatch'],[reaperStart,'camofox_inactivity_reaper_start_mismatch'],[pageClose,'camofox_inactivity_page_close_mismatch'],[reaperEnd,'camofox_inactivity_reaper_end_mismatch'],[reaperSessionClose,'camofox_inactivity_session_close_mismatch'],[staleStart,'camofox_stale_session_reaper_start_mismatch'],[staleClose,'camofox_stale_session_close_mismatch'],[staleEnd,'camofox_stale_session_reaper_end_mismatch'],[orphanStart,'camofox_orphan_reaper_start_mismatch'],[orphanClose,'camofox_orphan_page_close_mismatch'],[orphanEnd,'camofox_orphan_reaper_end_mismatch'],[pressureStart,'camofox_memory_pressure_start_mismatch'],[pressureClose,'camofox_memory_pressure_close_mismatch'],[pressureEnd,'camofox_memory_pressure_end_mismatch']]) {
    if(source.split(anchorText).length!==2)throw Error(errorCode);
  }
  const guardedIdleShutdown=`function scheduleBrowserIdleShutdown() {
  if (browserIdleTimer || sessions.size > 0 || !browser) return;
  browserIdleTimer = setTimeout(async () => {
    browserIdleTimer = null;
    const cleanupToken = paperclipGuard.tryBeginCleanup();
    if (!cleanupToken) return;
    const idleBrowser = browser;
    if (sessions.size > 0 || !idleBrowser) {
      cleanupToken.complete();
      return;
    }
    try {
      log('info', 'browser idle shutdown (no sessions)');
      await closeBrowserFully('idle_shutdown');
      if (idleBrowser.isConnected()) throw new Error('idle_browser_shutdown_unverified');
      cleanupToken.complete();
    } catch {
      cleanupToken.uncertain();
    }
  }, BROWSER_IDLE_TIMEOUT_MS);
}`;
  const guardedDestroyTab=destroyTab.replace('  const lock = tabLocks.get(tabId);',"  if (paperclipGuard.isReserved()) return false;\n  const lock = tabLocks.get(tabId);");
  const guardedDestroySession=destroySession.replace('  const key = normalizeUserId(userId);',"  if (paperclipGuard.isReserved()) return false;\n  const key = normalizeUserId(userId);");
  let result=source.replace(fly,'// Fly routing moved behind Paperclip guard.').replace(anchor,anchor+addition);
  let stagedPersistencePluginSource;
  if(recoveryBundle?.restoreColdContext===true){
    stagedPersistencePluginSource=stagePersistencePlugin(recoveryBundle.persistencePluginSource);
    result=recoveryServerSource.replace(fly,'// Fly routing moved behind Paperclip guard.').replace(anchor,anchor+addition);
    const keyAnchor='  const key = normalizeUserId(userId);\n  let session = sessions.get(key);';
    if(result.split(keyAnchor).length!==2)throw Error('camofox_cold_recovery_key_anchor_mismatch');
    result=result.replace(keyAnchor,`  const key = normalizeUserId(userId);\n  if (recoveryCreationUsers.has(key) && recoveryCreationUsers.get(key) !== recoveryDescriptor) throw new Error('recovery_cold_context_competing_creation');\n  let session = sessions.get(key);`);
    if(result.split('const sessions = new Map();').length!==2)throw Error('camofox_recovery_session_map_anchor_mismatch');
    result=result.replace('const sessions = new Map();','const sessions = new Map();\nconst recoveryCreationUsers = new Map();');
  }
  if(recoveryBundle!==undefined)result=result.replace(runtimeEndAnchor,runtimeEndAnchor+runtimeInit);
  if(recoveryBundle?.restoreColdContext===true){
    const restoreCall="    const session = await getSession(userId, {trace:false, recoveryDescriptor});";
    if(result.split(restoreCall).length!==2)throw Error('camofox_cold_restore_call_anchor_mismatch');
    result=result.replace(restoreCall,"    if (recoveryCreationUsers.has(userId)) throw new Error('recovery_cold_context_competing_creation');\n    recoveryCreationUsers.set(userId, recoveryDescriptor);\n    let session;\n    try { session = await getSession(userId, {trace:false, recoveryDescriptor}); }\n    finally { recoveryCreationUsers.delete(userId); }");
  }
  result=result.replace(destroyTab,guardedDestroyTab).replace(destroySession,guardedDestroySession)
    .replace(idleShutdownStart,guardedIdleShutdown)
    .replace(shutdown,shutdown.replace('  process.exit(0);','  paperclipGuard.close();\n  process.exit(0);'))
    .replace(closeOptions,closeOptions.replace('  clearLocks = true,','  clearLocks = true,\n  requireVerifiedClose = false,'))
    .replace(closeCall,"  if (requireVerifiedClose) await session.context.close();\n  else await session.context.close().catch(() => {});")
    .replace(reaperStart,reaperStart.replace('setInterval(() => {','setInterval(async () => {\n  const cleanupToken = paperclipGuard.tryBeginCleanup();\n  if (!cleanupToken) return;\n  try {'))
    .replace(pageClose,"            await safePageClose(tabState.page);\n            if (!tabState.page.isClosed()) throw new Error('inactive_page_close_unverified');\n            group.delete(tabId);")
    .replace(reaperSessionClose,"      await closeSession(userId, session, { reason: 'tab_reaper_empty_session', clearDownloads: true, clearLocks: true, requireVerifiedClose: true });")
    .replace(reaperEnd,"  if (sessions.size === 0) scheduleBrowserIdleShutdown();\n  cleanupToken.complete();\n  } catch {\n    cleanupToken.uncertain();\n  }\n}, 60_000);\n\n// Orphan page reaper")
    .replace(staleStart,`// Cleanup stale sessions\nsetInterval(async () => {\n  const cleanupToken = paperclipGuard.tryBeginCleanup();\n  if (!cleanupToken) return;\n  try {`)
    .replace(staleClose,"      await closeSession(userId, session, { reason: 'session_timeout', clearDownloads: true, clearLocks: true, requireVerifiedClose: true });")
    .replace(staleEnd,"  refreshTabLockQueueDepth();\n  cleanupToken.complete();\n  } catch {\n    cleanupToken.uncertain();\n  }\n}, 60_000);\n\n// Memory pressure eviction")
    .replace(orphanStart,orphanStart.replace('setInterval(() => {','setInterval(async () => {\n  const cleanupToken = paperclipGuard.tryBeginCleanup();\n  if (!cleanupToken) return;\n  try {'))
    .replace(orphanClose,"        await page.close({ runBeforeUnload: false });\n        if (!page.isClosed()) throw new Error('orphan_page_close_unverified');")
    .replace(orphanEnd,"  if (reaped > 0) log('warn', 'orphan page reaper closed leaked pages', { reaped });\n  cleanupToken.complete();\n  } catch {\n    cleanupToken.uncertain();\n  }\n}, 60_000);")
    .replace(pressureStart,pressureStart.replace('setInterval(() => {','setInterval(async () => {\n    const cleanupToken = paperclipGuard.tryBeginCleanup();\n    if (!cleanupToken) return;\n    try {'))
    .replace(pressureClose,"      await closeSession(oldestKey, session, {\n        reason: 'memory_pressure', clearDownloads: true, clearLocks: true,\n        requireVerifiedClose: true,\n      });")
    .replace(pressureEnd,"      usedRatio = 1 - (freeMem / totalMem);\n    }\n    cleanupToken.complete();\n    } catch {\n      cleanupToken.uncertain();\n    }\n  }, 30_000);\n}");
  const receipt={version:recoveryBundle?.restoreColdContext===true?2:1,originalSha256:hash(source),stagedSha256:hash(result),modulePath};
  if(stagedPersistencePluginSource){
    Object.assign(receipt,{originalPluginSha256:PERSISTENCE_PLUGIN_SHA256,stagedPluginSha256:hash(stagedPersistencePluginSource),persistenceClosureFiles:recoveryBundle.persistenceClosureFiles,persistenceClosureSha256:recoveryBundle.persistenceClosureSha256,persistenceLoaderSha256:recoveryBundle.persistenceLoaderSha256,persistencePackageSha256:recoveryBundle.persistencePackageSha256});
  }
  return {source:result,stagedPersistencePluginSource,receipt};
}
export function rollbackGuard(current,original,receipt){
  if(!receipt||receipt.version===2||Object.hasOwn(receipt,'originalPluginSha256')||Object.hasOwn(receipt,'stagedPluginSha256')||
     typeof current==='string'&&(current.includes("kind:'dedicated-persisted-state-v1'")||current.includes("recoveryDescriptor.kind !== 'dedicated-persisted-state-v1'")))throw Error('paired_plugin_rollback_required');
  if(receipt.originalSha256!==SOURCE_SHA256||hash(original)!==SOURCE_SHA256||hash(current)!==receipt.stagedSha256)throw Error('guard_rollback_ownership_mismatch');
  return original;
}
