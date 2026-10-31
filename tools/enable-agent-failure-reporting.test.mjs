import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,readdir,rm} from 'node:fs/promises';
import {resolve,dirname,basename} from 'node:path';
import {tmpdir} from 'node:os';
import {prepareAgentReportingConfig,patchAgentReportingConfig,BENCHMARK_TOOLS} from './enable-agent-failure-reporting.mjs';
const fixture='unrelated = "keep-private-value"\n[mcp_servers.w3bench_user]\nurl = "http://127.0.0.1:3000/api/agent/mcp"\nbearer_token_env_var = "W3_BENCH_TOKEN"\ndefault_tools_approval_mode = "auto"\nenabled_tools = '+JSON.stringify(BENCHMARK_TOOLS)+'\n\n[mcp_servers.w3bench_user.tools]\n'+BENCHMARK_TOOLS.map(t=>JSON.stringify(t)+' = { approval_mode = "approve" }').join('\n')+'\n\n[other]\nkeep = true\n';
test('profile patch adds only report and receipt, preserves unrelated data and is idempotent',()=>{
 const result=prepareAgentReportingConfig(fixture);assert.deepEqual(result.addedTools,['support.report','support.report_receipt']);assert.equal(result.enabledTools.length,8);
 assert.ok(result.text.startsWith('unrelated = "keep-private-value"\n'));assert.ok(result.text.endsWith('[other]\nkeep = true\n'));
 assert.ok(!result.text.includes('support.screenshot'));assert.equal(prepareAgentReportingConfig(result.text).changed,false);
 assert.equal(prepareAgentReportingConfig(fixture.replaceAll('\n','\r\n')).text.includes('\n')&&!prepareAgentReportingConfig(fixture.replaceAll('\n','\r\n')).text.includes('\r\n'),false);
 for(const altered of [fixture.replace('"auto"','"never"'),fixture.replace('runs.finish_task','support.screenshot.begin'),fixture.replace('approval_mode = "approve"','approval_mode = "deny"'),fixture+'\n[mcp_servers.w3bench_user]\n'])assert.throws(()=>prepareAgentReportingConfig(altered));
});
test('apply requires exact review hash, keeps private exact backup and leaves config unchanged on stale hash',async()=>{
 const directory=await mkdtemp(resolve(tmpdir(),'afr-config-unit-')),path=resolve(directory,'config.toml');
 try{await writeFile(path,fixture);const dry=await patchAgentReportingConfig({configPath:path});assert.equal(dry.applied,false);assert.equal(await readFile(path,'utf8'),fixture);
  await assert.rejects(patchAgentReportingConfig({configPath:path,apply:true,expectedSha256:'0'.repeat(64)}),/concurrent_change/);assert.deepEqual(await readdir(directory),['config.toml']);
  const result=await patchAgentReportingConfig({configPath:path,apply:true,expectedSha256:dry.beforeSha256});assert.equal(result.applied,true);assert.equal(await readFile(resolve(directory,result.privateBackupFile),'utf8'),fixture);
  assert.ok(!JSON.stringify(result).includes('keep-private-value'));assert.equal((await patchAgentReportingConfig({configPath:path,apply:true})).changed,false);
 }finally{assert.equal(dirname(directory),resolve(tmpdir()));assert.match(basename(directory),/^afr-config-unit-/);await rm(directory,{recursive:true,force:true});}
});
