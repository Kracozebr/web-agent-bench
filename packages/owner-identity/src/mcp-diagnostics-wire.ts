type Message=Record<string,unknown>;
const record=(v:unknown):v is Message=>v!==null&&typeof v==='object'&&!Array.isArray(v);
export interface DiagnosticWire {
  format:'json'|'sse'|'unknown';messages:Message[];complete:boolean;
  rewrite(map:(message:Message)=>Message):string;
}

/** Decode only bounded in-memory transport framing; callers retain projections. */
export function decodeDiagnosticWire(payload:string|Buffer,contentType:string):DiagnosticWire {
  const text=payload.toString();
  const unknown:DiagnosticWire={format:'unknown',messages:[],complete:false,rewrite:()=>text};
  if(Buffer.byteLength(text)>256*1024)return unknown;
  try{const value:unknown=JSON.parse(text);if(record(value))return{format:'json',messages:[value],complete:true,rewrite:map=>JSON.stringify(map(value))};}catch{/* SDK tool errors may use SSE even with responseMode=json. */}
  if(!contentType.includes('text/event-stream')&&!/^(?:event:|data:|:)/.test(text.trimStart()))return unknown;
  const frames=text.split(/\r?\n\r?\n/);if(frames.length>128)return unknown;
  const decoded=new Map<number,Message>();let complete=true;
  for(let index=0;index<frames.length;index++){
    const lines=frames[index]!.split(/\r?\n/),data=lines.filter(line=>line.startsWith('data:')).map(line=>line.slice(5).trimStart()).join('\n');
    if(!data)continue;
    try{const value:unknown=JSON.parse(data);if(!record(value)){complete=false;continue;}decoded.set(index,value);}catch{complete=false;}
  }
  if(!decoded.size)return unknown;
  return{format:'sse',messages:[...decoded.values()],complete,rewrite:map=>frames.map((frame,index)=>{
    const value=decoded.get(index);if(!value)return frame;
    let replaced=false;return frame.split(/\r?\n/).flatMap(line=>{
      if(!line.startsWith('data:'))return[line];if(replaced)return[];replaced=true;return['data: '+JSON.stringify(map(value))];
    }).join('\n');
  }).join('\n\n')};
}

export function attachDiagnosticMetadata(message:Message,requestId:unknown,metadata:Message):{message:Message;attached:boolean} {
  if(message.jsonrpc!=='2.0'||message.id!==requestId)return{message,attached:false};
  if(record(message.error)){
    const error=message.error;
    if(error.data!==undefined&&error.data!==null&&!record(error.data))return{message,attached:false};
    const data=record(error.data)?error.data:{};
    if(data._meta!==undefined&&!record(data._meta))return{message,attached:false};
    return{message:{...message,error:{...error,data:{...data,_meta:{...(record(data._meta)?data._meta:{}),'w3bench/diagnostics':metadata}}}},attached:true};
  }
  if(record(message.result)){
    const result=message.result;if(result._meta!==undefined&&!record(result._meta))return{message,attached:false};
    return{message:{...message,result:{...result,_meta:{...(record(result._meta)?result._meta:{}),'w3bench/diagnostics':metadata}}},attached:true};
  }
  return{message,attached:false};
}
