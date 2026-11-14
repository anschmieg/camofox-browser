import {RECOVERY_IDENTITY as I} from './pending_recovery.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const NONCE = /^[0-9a-f]{64}$/;
const DAY72 = 72 * 60 * 60;
const POLICY = ['version','authorized_uid','user_id','session_key','max_messages','issued_unix','expires_unix','project_creation','personal_content','arbitrary_code','work_mode'];
const JOURNAL = ['version','paused','tab_id','thread_id','operations'];
const OP = ['operation_id','test','phase','nonce'];
const APPROVAL = ['version','operation_id','original_tab_id','nonce','thread_id','user_id','session_key','create_one_replacement','observe_only','issued_unix','expires_unix'];
const GUARD = ['version','operationId','nonce','enrollment'];
const ENROLLMENT = ['userId','tabIds'];
const RECOVERY_BASE = ['version','operationId','userId','sessionKey','originalTabId','threadId','url','nonce','phase'];
const keys = (v, list) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === [...list].sort().join(',');
const integer = Number.isSafeInteger;
const validRecovery = (r, nonce, original) => {
  if (!r || !['created','verified'].includes(r.phase) || !keys(r, [...RECOVERY_BASE,'tabId'])) return false;
  return r.version === 1 && r.operationId === I.operationId && r.userId === I.userId && r.sessionKey === I.sessionKey &&
    r.originalTabId === original && r.threadId === I.threadId && r.url === I.url && r.nonce === nonce &&
    UUID.test(r.tabId) && r.tabId !== original;
};
function validSnapshot(s, request, now) {
  if (!keys(s,['policy','journal','creationApproval','guard','recovery']) || !keys(s.policy,POLICY)) return false;
  const p=s.policy;
  if(p.version!==1||p.authorized_uid!==1002||p.user_id!==I.userId||p.session_key!==I.sessionKey||p.max_messages!==10||
    !integer(p.issued_unix)||!integer(p.expires_unix)||p.expires_unix-p.issued_unix!==DAY72||
    ['project_creation','personal_content','arbitrary_code','work_mode'].some(k=>p[k]!==false)||!integer(now)||now<p.issued_unix||now>=p.expires_unix) return false;
  if(!keys(s.journal,JOURNAL)) return false;
  const j=s.journal;
  if(j.version!==1||j.paused!==false||!UUID.test(j.tab_id)||j.thread_id!==null||!Array.isArray(j.operations)||j.operations.length!==1||!keys(j.operations[0],OP)) return false;
  const op=j.operations[0];
  if(op.operation_id!==I.operationId||op.test!=='ping'||op.phase!=='mutation_started'||typeof op.nonce!=='string'||!NONCE.test(op.nonce)) return false;
  if(!keys(s.guard,GUARD)||s.guard.version!==2||s.guard.operationId!==I.operationId||s.guard.nonce!==op.nonce||!keys(s.guard.enrollment,ENROLLMENT)||
    s.guard.enrollment.userId!==I.userId||!Array.isArray(s.guard.enrollment.tabIds)||s.guard.enrollment.tabIds.length!==1||!UUID.test(s.guard.enrollment.tabIds[0])) return false;
  const original=s.guard.enrollment.tabIds[0], approval=s.creationApproval;
  if(j.tab_id!==original||!keys(approval,APPROVAL)||approval.version!==1||approval.operation_id!==I.operationId||approval.original_tab_id!==original||
    approval.nonce!==op.nonce||approval.thread_id!==I.threadId||approval.user_id!==I.userId||approval.session_key!==I.sessionKey||
    approval.create_one_replacement!==true||approval.observe_only!==true||!integer(approval.issued_unix)||!integer(approval.expires_unix)||
    approval.issued_unix<p.issued_unix||approval.issued_unix>now||now>=approval.expires_unix||approval.expires_unix>p.expires_unix) return false;
  if(request.stage==='create') return s.recovery===null;
  if(request.stage==='continue_create') {
    const r=s.recovery;
    return r!==null&&keys(r,RECOVERY_BASE)&&r.version===1&&r.operationId===I.operationId&&r.userId===I.userId&&
      r.sessionKey===I.sessionKey&&r.originalTabId===original&&r.threadId===I.threadId&&r.url===I.url&&r.nonce===op.nonce&&r.phase==='intent';
  }
  return validRecovery(s.recovery,op.nonce,original);
}

/** Pure synchronous authorization over an injected, trusted local-state snapshot. */
export function createPendingRecoveryAuthorizer({loadSnapshot,now}) {
  if(typeof loadSnapshot!=='function'||typeof now!=='function') throw Error('recovery_authorizer_dependencies_invalid');
  return function authorizeRecovery(request) {
    try {
      if(!keys(request,['operationId','nonce','originalTabId','stage'])||request.operationId!==I.operationId||
        typeof request.nonce!=='string'||!NONCE.test(request.nonce)||!UUID.test(request.originalTabId)||!['create','continue_create','observe'].includes(request.stage)) return false;
      const time=now(); if(!integer(time)) return false;
      const loaded=loadSnapshot(); if(loaded===null||typeof loaded!=='object'||typeof loaded.then==='function') return false;
      const snapshot=structuredClone(loaded);
      if(!validSnapshot(snapshot,request,time)||snapshot.journal.operations[0].nonce!==request.nonce||
        snapshot.guard.enrollment.tabIds[0]!==request.originalTabId) return false;
      return true;
    } catch { return false; }
  };
}
