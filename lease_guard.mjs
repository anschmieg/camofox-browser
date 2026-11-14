/** Inert server middleware candidate. Installation requires explicit approval.
 * Must run AFTER JSON parsing/auth and BEFORE every existing Camofox route.
 * Serializes the entire service conservatively; no implicit expiry unlock.
 * Storage is injected so the production integration must provide durable writes.
 */
import {timingSafeEqual} from 'node:crypto';
import {RECOVERY_IDENTITY} from './pending_recovery.mjs';
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&Buffer.byteLength(a)===Buffer.byteLength(b)&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const id=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{1,160}$/.test(x);
export function createLeaseGuard({key,enrollment,readEnrollment,store,recoverPending,authorizeHandoff}) {
  const snapshot=value=>{
    if(!value||Object.keys(value).sort().join(',')!=='tabIds,userId'||!id(value.userId)||!Array.isArray(value.tabIds)||
      !value.tabIds.length||value.tabIds.length>32||!value.tabIds.every(id)||new Set(value.tabIds).size!==value.tabIds.length)
      throw Error('lease_guard_enrollment_required');
    return Object.freeze({userId:value.userId,tabIds:Object.freeze([...value.tabIds])});
  };
  if(typeof key!=='string'||key.length<32||!store||typeof store.save!=='function'||typeof store.load!=='function')
    throw Error('lease_guard_configuration_required');
  const fixed=enrollment===undefined?null:snapshot(enrollment);
  if(!fixed&&typeof readEnrollment!=='function')throw Error('lease_guard_configuration_required');
  if(recoverPending!==undefined&&typeof recoverPending!=='function')throw Error('lease_guard_configuration_required');
  if(authorizeHandoff!==undefined&&typeof authorizeHandoff!=='function')throw Error('lease_guard_configuration_required');
  let held=store.load(),active=0,storageFailed=false,cleanupPending=0,cleanupUncertain=false;
  const valid=value=>value && id(value.operationId) && typeof value.nonce==='string' && /^[0-9a-f]{64}$/.test(value.nonce);
  if(held!==null){
    if(!valid(held)||held.version!==2||Object.keys(held).sort().join(',')!=='enrollment,nonce,operationId,version')throw Error('lease_guard_state_invalid');
    held=Object.freeze({...held,enrollment:snapshot(held.enrollment)});
  }
  const persist=value=>{try{store.save(value);held=value;}catch(error){storageFailed=true;throw error;}}; // Save must complete durably before HTTP ack.
  const recoveryFailureStatuses=new Set(['recovery_creation_uncertain','recovery_authority_required','recovery_owner_mismatch','recovery_storage_unavailable','recovery_journal_invalid','recovery_pending','recovery_request_invalid','recovery_busy']);
  const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const exact=(value,keys)=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
  const sanitizeRecovery=value=>{
    if(!value||typeof value!=='object'||Array.isArray(value))return {ok:false,status:'failed'};
    if(recoveryFailureStatuses.has(value.status)){
      if(exact(value,['ok','status'])&&value.ok===false)return {ok:false,status:value.status};
      return {ok:false,status:'failed'};
    }
    if(value.status==='created'){
      if(!exact(value,['ok','status','tabId'])||value.ok!==true||typeof value.tabId!=='string'||!uuid.test(value.tabId))
        return {ok:false,status:'failed'};
      return {ok:true,status:'created',tabId:value.tabId};
    }
    if(value.status==='verified'){
      if(!exact(value,['ok','status','tabId','plan'])||value.ok!==true||typeof value.tabId!=='string'||!uuid.test(value.tabId)||
        !exact(value.plan,['userId','tabId','threadId','url'])||value.plan.userId!==RECOVERY_IDENTITY.userId||
        value.plan.tabId!==value.tabId||value.plan.threadId!==RECOVERY_IDENTITY.threadId||value.plan.url!==RECOVERY_IDENTITY.url)
        return {ok:false,status:'failed'};
      return {ok:true,status:'verified',tabId:value.tabId,threadId:RECOVERY_IDENTITY.threadId};
    }
    return {ok:false,status:'failed'};
  };
  const guard=function guard(req,res,next) {
    const handoffRoute=req.path==='/paperclip/recovery-handoff';
    const recoveryRoute=req.path==='/paperclip/recovery';
    const leaseRoute=req.path==='/paperclip/lease';
    if(handoffRoute){
      if(req.method!=='POST'||!same(req.headers['x-paperclip-bridge-key'],key))return res.status(403).json({ok:false,error:'handoff_authority_required'});
      if(!authorizeHandoff)return res.status(404).json({ok:false,error:'handoff_unavailable'});
      const body=req.body&&typeof req.body==='object'?Object.freeze({...req.body}):req.body;
      if(!exact(body,['operationId','nonce','originalTabId','replacementTabId'])||
        body.operationId!==RECOVERY_IDENTITY.operationId||typeof body.nonce!=='string'||!/^[0-9a-f]{64}$/.test(body.nonce)||
        typeof body.originalTabId!=='string'||!uuid.test(body.originalTabId)||
        typeof body.replacementTabId!=='string'||!uuid.test(body.replacementTabId)||body.originalTabId===body.replacementTabId)
        return res.status(400).json({ok:false,error:'handoff_request_invalid'});
      if(storageFailed)return res.status(503).json({ok:false,error:'lease_storage_unavailable'});
      if(cleanupPending||cleanupUncertain||active)return res.status(423).json({ok:false,error:'shared_service_busy'});
      const heldAtStart=held;
      if(!heldAtStart||heldAtStart.version!==2||heldAtStart.operationId!==RECOVERY_IDENTITY.operationId||
        !same(heldAtStart.nonce,body.nonce)||!heldAtStart.enrollment||
        heldAtStart.enrollment.userId!==RECOVERY_IDENTITY.userId||heldAtStart.enrollment.tabIds.length!==1||
        ![body.originalTabId,body.replacementTabId].includes(heldAtStart.enrollment.tabIds[0])||
        req.headers['x-paperclip-operation']!==heldAtStart.operationId||!same(req.headers['x-paperclip-lease'],heldAtStart.nonce))
        return res.status(423).json({ok:false,error:'lease_not_recoverable'});
      active++;
      let settled=false;
      const finish=()=>{if(!settled){settled=true;active--;}};
      void (async()=>{
        try{
          let authorized;
          try{authorized=await authorizeHandoff(Object.freeze({operationId:body.operationId,nonce:body.nonce,
            originalTabId:body.originalTabId,replacementTabId:body.replacementTabId}));}
          catch{try{res.status(503).json({ok:false,error:'handoff_failed'});}catch{};return;}
          if(authorized!==true){try{res.status(403).json({ok:false,error:'handoff_not_authorized'});}catch{};return;}
          if(storageFailed){try{res.status(503).json({ok:false,error:'lease_storage_unavailable'});}catch{};return;}
          const currentTab=held?.enrollment?.tabIds?.[0];
          if(held!==heldAtStart||held.operationId!==body.operationId||!same(held.nonce,body.nonce)||
            held.version!==2||held.enrollment.userId!==RECOVERY_IDENTITY.userId||
            ![body.originalTabId,body.replacementTabId].includes(currentTab)){
            try{res.status(423).json({ok:false,error:'lease_not_recoverable'});}catch{};return;
          }
          if(currentTab===body.originalTabId){
            const replacement=Object.freeze({version:heldAtStart.version,operationId:heldAtStart.operationId,
              nonce:heldAtStart.nonce,enrollment:snapshot({userId:heldAtStart.enrollment.userId,tabIds:[body.replacementTabId]})});
            try{persist(replacement);}catch{try{res.status(503).json({ok:false,error:'lease_storage_unavailable'});}catch{};return;}
          }
          try{res.json({ok:true,status:'handoff_complete'});}catch{}
        }finally{finish();}
      })();
      return;
    }
    if(recoveryRoute){
      if(req.method!=='POST'||!same(req.headers['x-paperclip-bridge-key'],key))return res.status(403).json({ok:false,error:'recovery_authority_required'});
      if(!recoverPending)return res.status(404).json({ok:false,error:'recovery_unavailable'});
      const body=req.body;
      if(!body||Object.keys(body).sort().join(',')!=='nonce,operationId'||!id(body.operationId)||typeof body.nonce!=='string'||!/^[0-9a-f]{64}$/.test(body.nonce))
        return res.status(400).json({ok:false,error:'recovery_request_invalid'});
      if(storageFailed)return res.status(503).json({ok:false,error:'lease_storage_unavailable'});
      if(cleanupPending||cleanupUncertain)return res.status(423).json({ok:false,error:'shared_service_busy'});
      if(active)return res.status(423).json({ok:false,error:'shared_service_busy'});
      const heldAtStart=held;
      if(!heldAtStart||heldAtStart.operationId!==body.operationId||!same(heldAtStart.nonce,body.nonce)||heldAtStart.version!==2||!heldAtStart.enrollment||active||cleanupPending||cleanupUncertain)
        return res.status(423).json({ok:false,error:'lease_not_recoverable'});
      if(req.headers['x-paperclip-operation']!==heldAtStart.operationId||!same(req.headers['x-paperclip-lease'],heldAtStart.nonce))
        return res.status(423).json({ok:false,error:'lease_not_recoverable'});
      active++;
      let settled=false;
      const finish=()=>{if(!settled){settled=true;active--;}};
      void (async()=>{
        try{
          const value=await recoverPending(Object.freeze({operationId:heldAtStart.operationId,nonce:heldAtStart.nonce}));
          const stillHeld=held===heldAtStart&&held.operationId===body.operationId&&same(held.nonce,body.nonce);
          if(!stillHeld){try{res.status(423).json({ok:false,error:'lease_not_recoverable'});}catch{};return;}
          try{res.json(sanitizeRecovery(value));}catch{}
        }catch{
          try{res.status(503).json({ok:false,error:'recovery_failed'});}catch{}
        }finally{finish();}
      })();
      return;
    }
    const deny=(status,code)=>res.status(status).json({ok:false,error:code});
    if(storageFailed)return deny(503,'lease_storage_unavailable');
    if(cleanupPending||cleanupUncertain)return deny(423,'shared_service_busy');
    if(leaseRoute) {
      if(req.method!=='POST'||!same(req.headers['x-paperclip-bridge-key'],key))return deny(403,'lease_authority_required');
      const body=req.body;
      if(!body||!valid(body)||!['acquire','assert','release'].includes(body.action)||
        Object.keys(body).sort().join(',')!=='action,nonce,operationId')return deny(400,'lease_request_invalid');
      const matches=held&&held.operationId===body.operationId&&same(held.nonce,body.nonce);
      if(body.action==='acquire') {
        if(held&&!matches||active||cleanupPending||cleanupUncertain)return deny(423,'shared_service_busy');
        if(!held){
          let enrolled;
          try{enrolled=fixed||snapshot(readEnrollment());}catch{return deny(503,'lease_enrollment_unavailable');}
          try{persist(Object.freeze({version:2,operationId:body.operationId,nonce:body.nonce,enrollment:enrolled}));}catch{return deny(503,'lease_storage_unavailable');}
        }
      }else {
        if(!matches)return deny(423,'lease_not_owned');
        if(body.action==='release'){
          if(active)return deny(423,'shared_service_busy');
          try{persist(null);}catch{return deny(503,'lease_storage_unavailable');}
        }
      }
      return res.json({ok:true,result:{protocol:1,held:body.action!=='release',operationId:body.operationId}});
    }
    if(cleanupPending||cleanupUncertain)return deny(423,'shared_service_busy');
    if(held) {
      // Do not permit health, session reset, broad snapshots, tab lists, navigation,
      // browser stop, tracing or downloads during a Paperclip operation.
      const match=req.path.match(/^\/tabs\/([A-Za-z0-9_-]+)\/evaluate$/);
      if(req.method!=='POST'||!match||!held.enrollment.tabIds.includes(match[1])||
        req.body?.userId!==held.enrollment.userId||!same(req.headers['x-paperclip-lease'],held.nonce)||
        req.headers['x-paperclip-operation']!==held.operationId||!same(req.headers['x-paperclip-bridge-key'],key))
        return deny(423,'shared_service_reserved');
      // One outstanding evaluate at a time, including async DOM completion.
      if(active)return deny(423,'shared_service_busy');
    }else if(req.headers['x-paperclip-bridge-key']||req.headers['x-paperclip-lease'])return deny(423,'lease_required');
    active++;
    let finished=false;
    // 'close' does not prove an asynchronous evaluate stopped. A lost client
    // leaves the guard busy until handler completion or server restart/recovery.
    res.once('finish',()=>{if(!finished){finished=true;active--;}});
    next();
  };
  guard.isReserved=()=>Boolean(held)||storageFailed;
  guard.tryBeginCleanup=()=>{
    if(held||storageFailed||active||cleanupPending||cleanupUncertain)return null;
    cleanupPending++;
    let settled=false;
    return Object.freeze({
      complete(){if(settled)return;settled=true;cleanupPending--;},
      uncertain(){if(settled)return;settled=true;cleanupPending--;cleanupUncertain=true;}
    });
  };
  return guard;
}
