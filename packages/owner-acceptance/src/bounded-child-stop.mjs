const pause=ms=>new Promise(done=>setTimeout(done,ms));
const exited=child=>child.exitCode!==null||child.signalCode!==null;

/** Await actual child death, including signal exits, before releasing fault barriers. */
export async function stopDetachedChild(child,{graceMs=3000,killWaitMs=5000}={}){
 if(!child||exited(child))return;
 const signal=name=>{try{process.kill(-child.pid,name);}catch(error){if(error.code!=='ESRCH')throw error;}};
 const wait=async ms=>{const end=Date.now()+ms;while(!exited(child)&&Date.now()<end)await pause(20);return exited(child);};
 signal('SIGTERM');
 if(await wait(graceMs))return;
 signal('SIGKILL');
 if(!await wait(killWaitMs))throw Object.assign(new Error('acceptance_child_stop_not_observed'),{code:'ACCEPTANCE_CHILD_STOP_NOT_OBSERVED'});
}
