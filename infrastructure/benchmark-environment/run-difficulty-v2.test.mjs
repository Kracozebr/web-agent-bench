import assert from 'node:assert/strict';
import test from 'node:test';
import {parseDifficultyReferenceArguments} from './run-difficulty-v2.mjs';
const target='0x'+'2'.repeat(40);
test('wrapper accepts optional public recipient only for valid S1 modes and preserves omitted default',()=>{
 const base=['--task-id','S1','--mode','ranked','--env-id','bef-env-a'];
 assert.equal(parseDifficultyReferenceArguments(base).recipient,undefined);
 assert.equal(parseDifficultyReferenceArguments([...base,'--recipient',target]).recipient,target);
 assert.equal(parseDifficultyReferenceArguments(base.map(x=>x==='ranked'?'training':x).concat(['--recipient',target])).recipient,target);
 for(const id of ['S2','M1','H1'])assert.throws(()=>parseDifficultyReferenceArguments(base.map(x=>x==='S1'?id:x).concat(['--recipient',target])));
 for(const value of ['bad','0x'+'0'.repeat(40)])assert.throws(()=>parseDifficultyReferenceArguments([...base,'--recipient',value]));
 assert.throws(()=>parseDifficultyReferenceArguments([...base,'--recipient',target,'--recipient',target]));
});
