/** Private durable JSON storage. Single owner; crashed ownership fails closed.
 * Provision a dedicated 0700 directory first. Never reuse a browser profile.
 * Do not delete owner.lock until the previous process is proven stopped.
 */
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
export function openPrivateStore(directory,name='state.json') {
  if(!path.isAbsolute(directory)||!/^[-a-z0-9]+\.json$/.test(name))throw Error('private_store_path_required');
  const dir=fs.lstatSync(directory);
  if(!dir.isDirectory()||dir.isSymbolicLink()||dir.uid!==process.getuid()||(dir.mode&0o077))throw Error('private_store_directory_unsafe');
  const file=path.join(directory,name),lock=path.join(directory,name+'.owner.lock');
  const flags=fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW;
  const lockFd=fs.openSync(lock,flags,0o600);
  let closed=false,poisoned=false;
  const syncDir=()=>{const fd=fs.openSync(directory,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}};
  try{fs.writeFileSync(lockFd,JSON.stringify({pid:process.pid}));fs.fsyncSync(lockFd);syncDir();}catch(e){fs.closeSync(lockFd);throw e;}
  const ready=()=>{if(closed||poisoned)throw Error('private_store_unavailable');};
  return {
    load(){
      ready();let fd;
      try{fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);}catch(e){if(e.code==='ENOENT')return null;throw e;}
      try{const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.uid!==process.getuid()||(stat.mode&0o077)||stat.nlink!==1||stat.size>65536)throw Error('private_store_file_unsafe');
        return JSON.parse(fs.readFileSync(fd,'utf8'));
      }finally{fs.closeSync(fd);}
    },
    save(value){
      ready();const bytes=JSON.stringify(value);if(Buffer.byteLength(bytes)>65536)throw Error('private_store_bound');
      const tmp=path.join(directory,'.'+name+'.'+randomBytes(16).toString('hex'));
      let fd;
      try{fd=fs.openSync(tmp,flags,0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
        fs.renameSync(tmp,file);syncDir();
      }catch(e){poisoned=true;if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(tmp);}catch{}throw e;}
    },
    close(){if(closed)return;closed=true;fs.closeSync(lockFd);fs.unlinkSync(lock);syncDir();}
  };
}
