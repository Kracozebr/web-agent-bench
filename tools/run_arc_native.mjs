/** Windows host broker for one disposable ARC native job. No global client settings are written. */
import {spawn} from 'node:child_process';
import {mkdir,readFile,writeFile,rename,lstat,realpath,unlink} from 'node:fs/promises';
import {resolve,dirname,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {privateCaptureDirectory,sha256,ARC_NATIVE_TOOLS} from './arc-native-bridge.mjs';

export function transformNativeHelper(source) {
  const endpoint="const ENDPOINT = 'http://127.0.0.1:3000/api/agent/mcp';";
  const exec="      'exec', '--ephemeral', '--json', '--sandbox', 'read-only', '--skip-git-repo-check',";
  if(source.split(endpoint).length!==2||source.split(exec).length!==2||!source.includes('owner_identity'))throw new Error('native_helper_source_drift');
  // AICODE-NOTE: Keep auth hard-link lifecycle, private CODEX_HOME, parser and helper run limits byte-for-byte.
  return source.replace(endpoint,"const ENDPOINT = 'http://127.0.0.1:39001/api/agent/mcp';").replaceAll('owner_identity','w3bench_user').replace(exec,"      '--no-daemon', 'exec', '--ephemeral', '--json', '--sandbox', 'read-only', '--skip-git-repo-check',");
}
const sleep=ms=>new Promise(done=>setTimeout(done,ms));
async function regularFile(file) {const s=await lstat(file);if(!s.isFile()||s.isSymbolicLink())throw new Error('native_job_path_invalid');return s;}
async function boundedJson(file,max=1024*1024){const s=await regularFile(file);if(s.size>max)throw new Error('native_job_size_invalid');return JSON.parse(await readFile(file,'utf8'));}
async function validatePrivateDirectory(repoRoot,directory){
  let current=resolve(repoRoot);const target=resolve(directory);
  if(!target.startsWith(current+sep))throw new Error('native_job_path_invalid');
  for(const component of target.slice(current.length+1).split(sep)){
    current=resolve(current,component);const s=await lstat(current);
    if(!s.isDirectory()||s.isSymbolicLink()||(await realpath(current)).toLowerCase()!==current.toLowerCase())throw new Error('native_job_path_invalid');
  }
}
export async function runArcNativeBroker({repoRoot,captureId,codexExecutable,waitMs=12*60*1000}){
  if(process.platform!=='win32')throw new Error('native_broker_requires_windows');
  const directory=privateCaptureDirectory(repoRoot,captureId);let job;
  const until=Date.now()+waitMs;
  while(Date.now()<until){try{await validatePrivateDirectory(repoRoot,directory);job=await boundedJson(resolve(directory,'job.json'),64*1024);break;}catch(error){if(error.code!=='ENOENT')throw error;}await sleep(500);}
  if(!job)throw new Error('native_job_wait_timeout');
  if(job.schemaVersion!=='arc-native-job/v1'||job.captureId!==captureId||!/^[a-f0-9-]{36}$/.test(job.jobId)||!/^[a-f0-9]{64}$/.test(job.promptSha256)||job.credentialFile!=='credential.txt'||job.promptFile!=='handoff.txt'||JSON.stringify(job.enabledTools)!==JSON.stringify(ARC_NATIVE_TOOLS))throw new Error('native_job_invalid');
  const credentialPath=resolve(directory,'credential.txt'),promptPath=resolve(directory,'handoff.txt');
  await regularFile(credentialPath);await regularFile(promptPath);
  if(sha256(await readFile(promptPath))!==job.promptSha256)throw new Error('native_prompt_hash_mismatch');
  const helperPath=resolve(repoRoot,'infrastructure/owner-identity/run-codex-google-local.mjs');
  const original=await readFile(helperPath,'utf8'),transformed=transformNativeHelper(original);
  const copyPath=resolve(directory,'native-helper.mjs'),outputPath=resolve(directory,'native-summary.json');
  await writeFile(copyPath,transformed,{flag:'wx',mode:0o600});
  const executable=resolve(codexExecutable??resolve(repoRoot,'.local/codex-runner-inspection/package/vendor/x86_64-pc-windows-msvc/bin/codex.exe'));
  const pins={baseHelperSha256:sha256(Buffer.from(original)),transformedHelperSha256:sha256(Buffer.from(transformed)),nativeExeSha256:sha256(await readFile(executable)),codeModeHostSha256:sha256(await readFile(resolve(dirname(executable),'codex-code-mode-host.exe'))),packageManifestSha256:sha256(await readFile(resolve(dirname(executable),'../codex-package.json'))),brokerSha256:sha256(await readFile(fileURLToPath(import.meta.url))),bridgeSha256:sha256(await readFile(resolve(repoRoot,'tools/arc-native-bridge.mjs')))};
  const workspace=resolve(directory,'empty-workspace');await mkdir(workspace,{mode:0o700});
  let exited=false;
  try{
    const child=spawn(process.execPath,[copyPath,'--private-credential-file',credentialPath,'--nonsensitive-prompt-file',promptPath,'--sanitized-output-path',outputPath,'--codex-executable',executable,'--workspace',workspace,'--enabled-mcp-tools',JSON.stringify(ARC_NATIVE_TOOLS)],{cwd:repoRoot,windowsHide:true,stdio:['ignore','ignore','ignore']});
    const exitCode=await new Promise((done,fail)=>{child.once('error',fail);child.once('close',code=>done(code));});exited=true;
    const summary=await boundedJson(outputPath);
    if(sha256(await readFile(promptPath))!==job.promptSha256||sha256(await readFile(helperPath))!==pins.baseHelperSha256||sha256(await readFile(copyPath))!==pins.transformedHelperSha256)throw new Error('native_source_changed');
    const native={implementation:'native_codex_cli',clientVersion:summary.cliVersion?.replace(/^codex-cli /,''),promptSha256:job.promptSha256,status:summary.status,mcpToolCalls:summary.mcpToolCallCount??0,localToolCalls:summary.localToolCallCount??null,exitCode};
    const completed={schemaVersion:'arc-native-completed/v1',jobId:job.jobId,captureId,promptSha256:job.promptSha256,completedAt:new Date().toISOString(),native,sourcePins:pins,helperSummary:summary};
    await writeFile(resolve(directory,'completed.tmp'),JSON.stringify(completed),{flag:'wx',mode:0o600});await rename(resolve(directory,'completed.tmp'),resolve(directory,'completed.json'));
    return native;
  }finally{
    // Delete exactly the credential this completed helper consumed; no recursive directory cleanup.
    if(exited)await unlink(credentialPath).catch(error=>{if(error.code!=='ENOENT')throw error;});
  }
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const args=process.argv.slice(2);
  if(args.length!==2||args[0]!=='--capture-id'){process.stderr.write('Usage: node tools/run_arc_native.mjs --capture-id <captureId>\n');process.exitCode=2;}
  else try {const native=await runArcNativeBroker({repoRoot:resolve(dirname(fileURLToPath(import.meta.url)),'..'),captureId:args[1]});process.stdout.write(JSON.stringify(native)+'\n');}
  catch{process.stderr.write('arc_native_broker_failed (inspect private sanitized summary if present)\n');process.exitCode=1;}
}
