/** Decode bounded MCP JSON/SSE in memory; only `proof` may enter evidence. */
export function parseMcdWireText(text,contentType=''){
  const media=String(contentType).split(';',1)[0].trim().toLowerCase();
  const proof={contentType:['application/json','text/event-stream','text/plain'].includes(media)?media:'unknown',framing:'unparsed',rootKeys:[],hasMcpResponse:false,resultIsError:false,rpcErrorCode:null};
  if(typeof text!=='string'||Buffer.byteLength(text)>256*1024)return {value:undefined,proof};
  let value;
  try{value=JSON.parse(text);proof.framing='json';}catch{
    for(const frame of text.split(/\r?\n\r?\n/).slice(0,32)){
      const data=frame.split(/\r?\n/).filter(line=>line.startsWith('data:')).map(line=>line.slice(5).trimStart()).join('\n');
      if(!data)continue;
      try{const candidate=JSON.parse(data);if(candidate&&typeof candidate==='object'&&!Array.isArray(candidate)&&(candidate.result!==undefined||candidate.error!==undefined)){value=candidate;proof.framing='sse';}}catch{}
    }
  }
  if(value&&typeof value==='object'&&!Array.isArray(value)){
    proof.rootKeys=['jsonrpc','id','result','error'].filter(key=>Object.hasOwn(value,key));
    proof.hasMcpResponse=value.result!==undefined||value.error!==undefined;
    proof.resultIsError=value.result?.isError===true;
    const code=value.error?.code;if(Number.isInteger(code)&&code>=-2147483648&&code<=2147483647)proof.rpcErrorCode=code;
  }
  return {value,proof};
}

export async function readMcdWireResponse(response){
  const reader=response.body?.getReader();if(!reader)return parseMcdWireText('',response.headers.get('content-type'));
  const chunks=[];let bytes=0;
  try{while(true){const next=await reader.read();if(next.done)break;bytes+=next.value.byteLength;if(bytes>256*1024){
    // Do not await cancellation of a cloned response: its other tee branch may
    // be consumed by the SDK only after this fetch observer returns.
    void reader.cancel().catch(()=>{});const value=parseMcdWireText('',response.headers.get('content-type'));value.proof.wireBytesExceeded=true;return value;
  }chunks.push(next.value);}return parseMcdWireText(Buffer.concat(chunks).toString('utf8'),response.headers.get('content-type'));}
  finally{reader.releaseLock();}
}
