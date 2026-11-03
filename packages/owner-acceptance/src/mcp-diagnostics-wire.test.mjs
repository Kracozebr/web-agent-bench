import assert from 'node:assert/strict';
import test from 'node:test';
import {parseMcdWireText,readMcdWireResponse} from './mcp-diagnostics-wire.mjs';
test('real SDK SSE validation errors yield safe protocol identity without text or arguments',()=>{
  const canary='CANARY_PRIVATE_RESPONSE_not_real';const body={jsonrpc:'2.0',id:7,result:{isError:true,content:[{type:'text',text:canary}]}};
  const decoded=parseMcdWireText('event: message\ndata: '+JSON.stringify(body)+'\n\n','text/event-stream; charset=utf-8');
  assert.equal(decoded.value.result.isError,true);assert.deepEqual(decoded.proof,{contentType:'text/event-stream',framing:'sse',rootKeys:['jsonrpc','id','result'],hasMcpResponse:true,resultIsError:true,rpcErrorCode:null});assert(!JSON.stringify(decoded.proof).includes(canary));
});
test('response observer stops a growing stream before retaining an oversized wire body',async()=>{
  const response=new Response('x'.repeat(256*1024+1),{headers:{'content-type':'text/event-stream'}});
  const decoded=await readMcdWireResponse(response);assert.equal(decoded.value,undefined);assert.equal(decoded.proof.hasMcpResponse,false);assert.equal(decoded.proof.wireBytesExceeded,true);
  const valid=await readMcdWireResponse(new Response('{"jsonrpc":"2.0","id":1,"result":{}}',{headers:{'content-type':'application/json'}}));assert.equal(valid.proof.framing,'json');assert.equal(valid.proof.hasMcpResponse,true);
});
test('JSON, unparsed and oversized wire stay distinguishable without fabricated successful replies',()=>{
  assert.equal(parseMcdWireText('{"jsonrpc":"2.0","id":7,"error":{"code":-32602}}','application/json').proof.rpcErrorCode,-32602);
  for(const text of ['not-json','data: malformed\n\n','x'.repeat(256*1024+1)]){const {proof}=parseMcdWireText(text,'text/event-stream');assert.equal(proof.framing,'unparsed');assert.equal(proof.hasMcpResponse,false);assert.equal(proof.resultIsError,false);}
});
