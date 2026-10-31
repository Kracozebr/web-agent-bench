export const SOURCE_READ_TOTAL_TIMEOUT_MS = 15_000;
export const SOURCE_READ_RETRY_BACKOFF_MS = 250;
export const SOURCE_READ_MAX_ATTEMPTS = 2;

const TRANSIENT_NETWORK_CODES = new Set(['ECONNRESET','ECONNREFUSED','ENOTFOUND','EAI_AGAIN','EHOSTUNREACH','ENETUNREACH',
  'ETIMEDOUT','UND_ERR_CONNECT_TIMEOUT','UND_ERR_HEADERS_TIMEOUT','UND_ERR_SOCKET']);

/** Static Node transport codes only: never classify an RPC response or inspect provider text. */
export function transientNetworkBeforeResponse(error: unknown): boolean {
  let value=error,knownNetwork=false;const seen=new Set<unknown>();
  for(let depth=0;depth<4&&value&&typeof value==='object'&&!seen.has(value);depth++) {
    seen.add(value);const record=value as {name?:unknown;code?:unknown;cause?:unknown};
    if(['AbortError','TimeoutError','TLSError','CertificateError'].includes(String(record.name)))return false;
    if(record.code!==undefined){
      if(typeof record.code!=='string'||!TRANSIENT_NETWORK_CODES.has(record.code))return false;
      knownNetwork=true;
    }
    value=record.cause;
  }
  // A truncated or cyclic cause chain is not enough proof for another wire request.
  return (value===null||value===undefined)&&knownNetwork;
}

export type ProxyReadForwardingHooks = {
  fetch?: typeof globalThis.fetch;
  now?: ()=>number;
  sleep?: (milliseconds:number)=>Promise<void>;
  timeoutSignal?: (milliseconds:number)=>AbortSignal;
};

/**
 * AICODE-NOTE: Called only with the existing validated/serialized read-only proxy request.
 * Source retries consume wire budget and one shared deadline; response/body/RPC validation
 * stays with the caller. Local requests and any received HTTP response are never retried.
 */
export async function forwardValidatedProxyRead(input:{
  source:boolean;targetUrl:string;serialized:string;
  reserveRetry:()=>boolean;onAttempt:(retry:boolean)=>void;onNetworkFailure:()=>void;
  onRetryOutcome:(reason:'response'|'exhausted'|'budget_denied'|'deadline_exhausted')=>void;
},hooks:ProxyReadForwardingHooks={}):Promise<Response> {
  const fetcher=hooks.fetch??globalThis.fetch,now=hooks.now??(()=>performance.now());
  const sleep=hooks.sleep??((ms:number)=>new Promise<void>(resolve=>setTimeout(resolve,ms)));
  const signal=hooks.timeoutSignal??((ms:number)=>AbortSignal.timeout(ms));
  const deadline=now()+SOURCE_READ_TOTAL_TIMEOUT_MS;
  for(let attempt=0;attempt<(input.source?SOURCE_READ_MAX_ATTEMPTS:1);attempt++){
    const remaining=Math.floor(deadline-now());
    if(remaining<=0){
      if(input.source)input.onRetryOutcome('deadline_exhausted');
      throw new Error('proxy_read_total_deadline_exhausted');
    }
    input.onAttempt(attempt>0);
    try {
      const response=await fetcher(input.targetUrl,{method:'POST',headers:{'content-type':'application/json'},body:input.serialized,signal:signal(remaining)});
      if(attempt>0)input.onRetryOutcome('response');
      return response;
    }catch(error){
      if(attempt>0)input.onRetryOutcome('exhausted');
      if(!input.source||!transientNetworkBeforeResponse(error))throw error;
      input.onNetworkFailure();
      if(attempt>0)throw error;
      if(deadline-now()<=SOURCE_READ_RETRY_BACKOFF_MS){input.onRetryOutcome('deadline_exhausted');throw error;}
      await sleep(SOURCE_READ_RETRY_BACKOFF_MS);
      if(deadline-now()<=0){input.onRetryOutcome('deadline_exhausted');throw error;}
      if(!input.reserveRetry()){input.onRetryOutcome('budget_denied');throw error;}
    }
  }
  throw new Error('proxy_read_attempts_exhausted');
}
