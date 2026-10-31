import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {stopDetachedChild} from './bounded-child-stop.mjs';

test('bounded stop observes actual SIGKILL exit before returning and supports a second stop',async()=>{
 const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});process.stdout.write('ready\\n');setInterval(()=>{},1000)"],{detached:true,stdio:['ignore','pipe','ignore']});
 try{
  await once(child.stdout,'data');
  await stopDetachedChild(child,{graceMs:50,killWaitMs:2000});
  assert.equal(child.exitCode,null);
  assert.equal(child.signalCode,'SIGKILL');
  await stopDetachedChild(child,{graceMs:50,killWaitMs:2000});
 }finally{if(child.exitCode===null&&child.signalCode===null)process.kill(-child.pid,'SIGKILL');}
});
