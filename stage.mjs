#!/usr/bin/env node
/** Offline staging only. Never replaces source, installs, or restarts services. */
import fs from 'node:fs';
import path from 'node:path';
import {stageGuard,rollbackGuard,PERSISTENCE_PLUGIN_SHA256,verifiedPersistenceClosure,readRegularBounded} from './stage_guard.mjs';
const args=process.argv.slice(2);
const [action,sourceFile,outputDirectory,moduleOrOriginal,receiptFile,domSha256,pluginSourceFile,pluginSha256]=args;
const handoffFiles={policyFile:'/var/lib/chatgpt-sandbox-broker/policy.json',journalFile:'/var/lib/chatgpt-sandbox-broker/journal.json',approvalFile:'/var/lib/chatgpt-sandbox-broker/recovery-approval.json',handoffFile:'/var/lib/chatgpt-sandbox-broker/pending-handoff.json'};
try {
 if(!['stage','stage-recovery','stage-cold-recovery','stage-cold-handoff','rollback'].includes(action)||!sourceFile||!outputDirectory||!moduleOrOriginal||
  args.length!==(action==='stage'?4:action==='stage-recovery'?6:action==='stage-cold-recovery'||action==='stage-cold-handoff'?8:5)||
  !path.isAbsolute(outputDirectory)||fs.existsSync(outputDirectory))throw Error('arguments');
 const source=readRegularBounded(sourceFile).toString('utf8');
 const isCold=['stage-cold-recovery','stage-cold-handoff'].includes(action);
 if(isCold&&(!pluginSourceFile||pluginSha256!==PERSISTENCE_PLUGIN_SHA256))throw Error('persistence_plugin_input_invalid');
 const closure=isCold?verifiedPersistenceClosure(pluginSourceFile):undefined;
 const recoveryBundle=['stage-recovery','stage-cold-recovery','stage-cold-handoff'].includes(action)?{
  domSource:readRegularBounded(receiptFile,100_000).toString('utf8'),domSha256,
  ...(isCold?{restoreColdContext:true,persistencePluginSource:readRegularBounded(pluginSourceFile).toString('utf8'),persistenceClosureFiles:closure.files,persistenceClosureSha256:closure.sha256,persistenceLoaderSha256:closure.loaderSha256,persistencePackageSha256:closure.packageSha256}:{}),
  ...(action==='stage-cold-handoff'?{handoffFiles}:{})}:undefined;
 const result=action!=='rollback'?stageGuard(source,moduleOrOriginal,recoveryBundle):{
  source:rollbackGuard(source,readRegularBounded(moduleOrOriginal).toString('utf8'),JSON.parse(readRegularBounded(receiptFile,100_000).toString('utf8')))};
 // Only create a new stage directory after all source checks pass.
 fs.mkdirSync(outputDirectory,{mode:0o700});
 fs.writeFileSync(path.join(outputDirectory,'server.js'),result.source,{flag:'wx',mode:0o600});
 if(result.receipt){
  fs.writeFileSync(path.join(outputDirectory,'original-server.js'),source,{flag:'wx',mode:0o600});
  if(result.stagedPersistencePluginSource){
   const originalPlugin=readRegularBounded(pluginSourceFile).toString('utf8');
   fs.writeFileSync(path.join(outputDirectory,'original-persistence-plugin.js'),originalPlugin,{flag:'wx',mode:0o600});
   fs.writeFileSync(path.join(outputDirectory,'persistence-plugin.js'),result.stagedPersistencePluginSource,{flag:'wx',mode:0o600});
  }
  fs.writeFileSync(path.join(outputDirectory,'receipt.json'),JSON.stringify(result.receipt,null,2)+'\n',{flag:'wx',mode:0o600});
 }
 process.stdout.write('Offline '+action+' files prepared; no installation performed\n');
}catch{process.stderr.write('Usage: stage.mjs stage SOURCE NEW_ABSOLUTE_DIR /absolute/guard_bootstrap.mjs\n       stage.mjs stage-recovery SOURCE NEW_ABSOLUTE_DIR /absolute/guard_bootstrap.mjs DOM_SOURCE TRUSTED_DOM_SHA256\n       stage.mjs stage-cold-recovery SOURCE NEW_ABSOLUTE_DIR /absolute/guard_bootstrap.mjs DOM_SOURCE TRUSTED_DOM_SHA256 PLUGIN_SOURCE PLUGIN_SHA256\n       stage.mjs stage-cold-handoff SOURCE NEW_ABSOLUTE_DIR /absolute/guard_bootstrap.mjs DOM_SOURCE TRUSTED_DOM_SHA256 PLUGIN_SOURCE PLUGIN_SHA256\n       stage.mjs rollback CURRENT NEW_ABSOLUTE_DIR ORIGINAL RECEIPT\nSource/ownership/argument checks failed; existing files are never replaced\n');process.exitCode=1;}
