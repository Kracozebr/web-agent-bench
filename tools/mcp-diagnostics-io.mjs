/** Enforce response size before retaining a complete untrusted response. */
export async function readBoundedDiagnosticText(response,maxBytes,code){
  if(Number(response.headers?.get?.('content-length'))>maxBytes)throw new Error(code);
  if(!response.body?.getReader){const text=await response.text();if(Buffer.byteLength(text)>maxBytes)throw new Error(code);return text;}
  const reader=response.body.getReader(),chunks=[];let count=0;try{for(;;){const {done,value}=await reader.read();if(done)break;count+=value.length;if(count>maxBytes)throw new Error(code);chunks.push(Buffer.from(value));}return Buffer.concat(chunks).toString('utf8');}finally{await reader.cancel().catch(()=>{});}
}
