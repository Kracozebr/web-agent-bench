import test from 'node:test';
import assert from 'node:assert/strict';
import {capturePorts} from './capture-ports.mjs';
test('capture relay respects published RPC B override independently of RPC A',()=>{
  assert.deepEqual(capturePorts({BEF_LOCAL_RPC_B_HOST_PORT:'29545'}),{rpcA:18545,rpcB:29545});
  assert.deepEqual(capturePorts({}),{rpcA:18545,rpcB:28545});
  assert.deepEqual(capturePorts({BEF_LOCAL_RPC_A_HOST_PORT:'18546',BEF_LOCAL_RPC_B_HOST_PORT:'29545'}),{rpcA:18546,rpcB:29545});
});
test('invalid configured relay port fails rather than falling back to a different endpoint',()=>{
  for(const value of ['','0','65536','28545/path','-1'])assert.throws(()=>capturePorts({BEF_LOCAL_RPC_B_HOST_PORT:value}));
});
