/** Prepare only the reviewed two-tool addition. Dry run by default; never print configuration or credentials. */
import {createHash,randomUUID} from 'node:crypto';
import {readFile,writeFile,lstat,rename,unlink} from 'node:fs/promises';
import {resolve,dirname,basename} from 'node:path';
import {fileURLToPath} from 'node:url';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export const BENCHMARK_TOOLS=['identity.preflight','runs.accept_launch_intent','runs.current_task','runs.task_action','runs.task_action_status','runs.finish_task'];
export const TEXT_REPORT_TOOLS=['support.report','support.report_receipt'];
export function prepareAgentReportingConfig(text){
 const newline=text.includes('\r\n')?'\r\n':'\n';
 const section='[mcp_servers.w3bench_user]',toolSection='[mcp_servers.w3bench_user.tools]';
 const starts=[...text.matchAll(/^\[mcp_servers\.w3bench_user\]\r?$/gm)];
 const toolStarts=[...text.matchAll(/^\[mcp_servers\.w3bench_user\.tools\]\r?$/gm)];
 if(starts.length!==1||toolStarts.length!==1)throw new Error('reporting_profile_shape_invalid');
 const start=starts[0].index,endMatch=text.slice(start+section.length).match(/\n\[/),end=endMatch?start+section.length+endMatch.index+1:text.length;
 const profile=text.slice(start,end);
 if(!/^default_tools_approval_mode\s*=\s*"auto"\s*$/m.test(profile))throw new Error('reporting_approval_policy_drift');
 const match=profile.match(/^enabled_tools\s*=\s*\[([^\]]*)\]/m);if(!match)throw new Error('reporting_allowlist_missing');
 const names=[...match[1].matchAll(/"([A-Za-z0-9_.]+)"/g)].map(x=>x[1]);
 if(match[1].replace(/"[A-Za-z0-9_.]+"|[\s,]/g,'')||new Set(names).size!==names.length||
   BENCHMARK_TOOLS.some(name=>!names.includes(name))||names.some(name=>![...BENCHMARK_TOOLS,...TEXT_REPORT_TOOLS].includes(name)))throw new Error('reporting_allowlist_drift');
 const missing=TEXT_REPORT_TOOLS.filter(name=>!names.includes(name));
 let updated=profile;
 if(missing.length){const replacement='enabled_tools = ['+newline+[...names,...missing].map(name=>'  '+JSON.stringify(name)).join(','+newline)+newline+']';updated=profile.replace(match[0],replacement);}
 let output=text.slice(0,start)+updated+text.slice(end);
 const toolStart=output.indexOf(toolSection),tail=output.slice(toolStart+toolSection.length),next=tail.match(/\n\[/),toolEnd=next?toolStart+toolSection.length+next.index+1:output.length;
 let tools=output.slice(toolStart,toolEnd);
 for(const name of [...BENCHMARK_TOOLS,...TEXT_REPORT_TOOLS]){
   const escaped=name.replaceAll('.','\\.');const line=new RegExp('^"'+escaped+'"\\s*=\\s*\\{\\s*approval_mode\\s*=\\s*"approve"\\s*\\}\\s*$','m');
   const any=new RegExp('^"'+escaped+'"\\s*=','m');
   if(any.test(tools)&&!line.test(tools))throw new Error('reporting_tool_approval_drift');
   if(!any.test(tools)){if(!TEXT_REPORT_TOOLS.includes(name))throw new Error('reporting_tool_approval_missing');tools=tools.replace(/\s*$/,'')+newline+JSON.stringify(name)+' = { approval_mode = "approve" }'+newline;}
 }
 output=output.slice(0,toolStart)+tools+output.slice(toolEnd);
 return {text:output,changed:output!==text,enabledTools:[...names,...missing],addedTools:missing};
}
export async function patchAgentReportingConfig({configPath,apply=false,expectedSha256}){
 const path=resolve(configPath),meta=await lstat(path);if(!meta.isFile()||meta.isSymbolicLink()||meta.size>1024*1024)throw new Error('reporting_config_file_invalid');
 const before=await readFile(path),beforeSha256=sha(before),plan=prepareAgentReportingConfig(before.toString('utf8'));
 const safe={changed:plan.changed,enabledTools:plan.enabledTools,addedTools:plan.addedTools,beforeSha256,afterSha256:sha(Buffer.from(plan.text)),applied:false};
 if(!apply||!plan.changed)return safe;
 if(!/^[a-f0-9]{64}$/.test(expectedSha256??'')||expectedSha256!==beforeSha256)throw new Error('reporting_config_concurrent_change');
 const suffix=randomUUID(),backup=resolve(dirname(path),basename(path)+'.afr-backup-'+suffix),temporary=resolve(dirname(path),'.afr-config-'+suffix+'.tmp');
 await writeFile(backup,before,{flag:'wx',mode:0o600});
 try{
  await writeFile(temporary,plan.text,{flag:'wx',mode:0o600});
  if(sha(await readFile(path))!==beforeSha256)throw new Error('reporting_config_concurrent_change');
  await rename(temporary,path);
  const after=await readFile(path);if(sha(after)!==safe.afterSha256)throw new Error('reporting_config_postwrite_mismatch');
  return {...safe,applied:true,privateBackupFile:basename(backup)};
 }finally{await unlink(temporary).catch(error=>{if(error.code!=='ENOENT')throw error;});}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const args=process.argv.slice(2),apply=args.includes('--apply'),hashIndex=args.indexOf('--expected-sha256');
 if(args.some((arg,index)=>arg!=='--apply'&&arg!=='--expected-sha256'&&!(hashIndex>=0&&index===hashIndex+1))||hashIndex>=0&&!args[hashIndex+1]||args.filter(x=>x==='--apply').length>1||args.filter(x=>x==='--expected-sha256').length>1){process.stderr.write('reporting_config_arguments_invalid\n');process.exitCode=2;}
 else try{const result=await patchAgentReportingConfig({configPath:resolve(process.env.USERPROFILE,'.codex/config.toml'),apply,expectedSha256:hashIndex>=0?args[hashIndex+1]:undefined});process.stdout.write(JSON.stringify(result)+'\n');}
 catch(error){process.stderr.write((/^reporting_[a-z_]+$/.test(error.message)?error.message:'reporting_config_failed')+'\n');process.exitCode=1;}
}
