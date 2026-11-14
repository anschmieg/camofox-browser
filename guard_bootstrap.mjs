/** Imported only by the separately approved staged Camofox server candidate. */
import fs from 'node:fs';
import path from 'node:path';
import {openPrivateStore} from './private_store.mjs';
import {createLeaseGuard} from './lease_guard.mjs';
import {createPendingRecovery} from './pending_recovery.mjs';
import {createPendingRecoveryBrowser} from './pending_recovery_browser.mjs';
import {makePinnedPendingRecoveryVerifier} from './pending_recovery_verify.mjs';
import {createPendingHandoffAuthorizer} from './pending_handoff_authorize.mjs';
import {createPendingRecoveryAuthorizer} from './pending_recovery_authorize.mjs';
function privatePath(filename) {
  if(typeof filename!=='string'||!path.isAbsolute(filename)||path.normalize(filename)!==filename)throw Error('guard_private_path_required');
  let current=path.dirname(filename);
  while(true){
    const stat=fs.lstatSync(current);
    if(!stat.isDirectory()||stat.isSymbolicLink()||![0,process.getuid()].includes(stat.uid)||
      ((stat.mode&0o022)&&!(stat.uid===0&&(stat.mode&0o1000))))throw Error('guard_private_path_required');
    if(current===path.dirname(current))break;
    current=path.dirname(current);
  }
}
export function readPrivateEnrollment(filename) {
  privatePath(filename);
  const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{
    const stat=fs.fstatSync(fd);
    if(!stat.isFile()||stat.uid!==process.getuid()||(stat.mode&0o077)||stat.nlink!==1||stat.size>8192)throw Error('guard_private_enrollment_required');
    return JSON.parse(fs.readFileSync(fd,'utf8'));
  }finally{fs.closeSync(fd);}
}
export function loadGuard(configPath,recoveryRuntime,handoffRuntime) {
  privatePath(configPath);
  const fd=fs.openSync(configPath,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  let config;
  try{const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.uid!==process.getuid()||(stat.mode&0o077)||stat.nlink!==1||stat.size>8192)throw Error('guard_private_config_required');config=JSON.parse(fs.readFileSync(fd,'utf8'));}
  finally{fs.closeSync(fd);}
  if(config.version!==1||config.enabled!==true)throw Error('guard_disabled');
  if(typeof config.enrollmentFile!=='string'||!path.isAbsolute(config.enrollmentFile))throw Error('guard_private_enrollment_required');
  const enrollmentFile=config.enrollmentFile;
  const store=openPrivateStore(config.stateDirectory,'guard.json');
  let recoveryStore=null;
  try{
    let recoverPending,authorizeHandoff;
    if(handoffRuntime!==undefined&&(!handoffRuntime||recoveryRuntime===undefined||
      Object.keys(handoffRuntime).sort().join(',')!=='enabled,loadBrokerState,now'||handoffRuntime.enabled!==true||
      typeof handoffRuntime.loadBrokerState!=='function'||typeof handoffRuntime.now!=='function'))throw Error('handoff_runtime_invalid');
    if(recoveryRuntime!==undefined){
      if(!recoveryRuntime||recoveryRuntime.enabled!==true||!(recoveryRuntime.sessions instanceof Map)||
        typeof recoveryRuntime.normalizeUserId!=='function'||typeof recoveryRuntime.createTabState!=='function'||
        typeof recoveryRuntime.makeTabId!=='function'||!Number.isSafeInteger(recoveryRuntime.maxTabsPerSession)||
        !Number.isSafeInteger(recoveryRuntime.maxTabsGlobal)||
        typeof recoveryRuntime.getTotalTabCount!=='function'||Object.hasOwn(recoveryRuntime,'verifyReadOnly'))throw Error('recovery_runtime_invalid');
      const hasLoader=Object.hasOwn(recoveryRuntime,'loadCreationState'),hasNow=Object.hasOwn(recoveryRuntime,'now');
      if(Object.hasOwn(recoveryRuntime,'authorizeRecovery')||hasLoader!==hasNow||
        (hasLoader&&(typeof recoveryRuntime.loadCreationState!=='function'||typeof recoveryRuntime.now!=='function')))throw Error('recovery_runtime_invalid');
      const verifyReadOnly=makePinnedPendingRecoveryVerifier({domSource:recoveryRuntime.domSource,domSha256:recoveryRuntime.domSha256});
      recoveryStore=openPrivateStore(config.stateDirectory,'pending-recovery.json');
      const browser=createPendingRecoveryBrowser({...recoveryRuntime,verifyReadOnly});
      const authorizeRecovery=hasLoader?createPendingRecoveryAuthorizer({now:recoveryRuntime.now,loadSnapshot:()=>{
        const loaded=recoveryRuntime.loadCreationState();
        if(!loaded||typeof loaded!=='object'||Array.isArray(loaded)||Object.keys(loaded).sort().join(',')!=='creationApproval,journal,policy')throw Error('recovery_creation_state_invalid');
        return {...loaded,guard:store.load(),recovery:recoveryStore.load()};
      }}):undefined;
      const controller=createPendingRecovery({store:recoveryStore,getReservation:()=>store.load(),
        createReplacement:browser.createReplacement,verifyReplacement:browser.verifyReplacement,...(authorizeRecovery?{authorizeRecovery}:{})});
      recoverPending=request=>controller.recover(request);
      if(handoffRuntime!==undefined){
        authorizeHandoff=createPendingHandoffAuthorizer({now:handoffRuntime.now,verifyReadOnly:browser.verifyReplacement,
          loadSnapshot:()=>{
            const broker=handoffRuntime.loadBrokerState();
            if(!broker||typeof broker!=='object'||Array.isArray(broker)||
              Object.keys(broker).sort().join(',')!=='approval,handoff,journal,policy')throw Error('handoff_broker_state_invalid');
            return {...broker,guard:store.load(),recovery:recoveryStore.load()};
          }});
      }
    }
    const middleware=createLeaseGuard({key:config.bridgeKey,readEnrollment:()=>readPrivateEnrollment(enrollmentFile),store,recoverPending,authorizeHandoff});
    return {middleware,isReserved:()=>middleware.isReserved(),tryBeginCleanup:()=>middleware.tryBeginCleanup(),
      close:()=>{try{if(recoveryStore)recoveryStore.close();}finally{store.close();}}};
  }
  catch(e){
    if(recoveryStore){try{recoveryStore.close();}catch{}}
    try{store.close();}catch{}
    throw e;
  }
}
