const ADDRESS=/^0x[0-9a-f]{40}$/i;
const validAddress=value=>typeof value==='string'&&ADDRESS.test(value)&&!/^0x0{40}$/i.test(value);
const requiredRecipient=task=>task.taskId==='M1'?task.objective?.paymentRequirements?.recipient:
  task.taskId==='S2'?task.objective?.completePaymentRequirements?.recipient:
  ['S3','M2'].includes(task.taskId)?task.objective?.required?.recipient:null;

// AICODE-NOTE: A healthy HTTP server is insufficient when an old sealed catalog
// names a different payee. Check every required recipient before serving users.
export function assertPaymentReadiness({manifest,health,allowedEnvironmentIds}) {
  const identity=manifest?.executionIdentity;
  if(!identity||health?.status!=='ready'||health.boundary!=='benchmark-environment-api'||
    health.manifestSha256!==identity.environmentManifestSha256||health.applicationSourceSha256!==identity.x402ServiceSha256||
    !Array.isArray(health.environments)||!Array.isArray(allowedEnvironmentIds)||allowedEnvironmentIds.length<1)
    throw new Error('google_local_payment_readiness_unavailable');
  const tasks=[...(manifest.cases?.training??[]),...(manifest.cases?.ranked??[])];
  const required=tasks.filter(t=>['M1','S2','S3','M2'].includes(t.taskId)).map(requiredRecipient);
  if(tasks.length!==15||required.some(value=>!validAddress(value)))throw new Error('google_local_payment_case_identity_invalid');
  const payees=allowedEnvironmentIds.map(envId=>{
    const entries=health.environments.filter(env=>env.envId===envId);
    if(entries.length!==1)throw new Error('google_local_payment_readiness_unavailable');
    const env=entries[0];
    const facilitator=env.facilitator;
    const value=facilitator&&Object.hasOwn(facilitator,'paymentRecipient')?facilitator.paymentRecipient:facilitator?.address;
    return validAddress(value)?value.toLowerCase():null;
  });
  if(required.some(value=>!payees.includes(value.toLowerCase())))throw new Error('google_local_payment_recipient_incompatible');
  return {status:'ready',requiredPaymentCases:required.length,compatibleRequiredPaymentCases:required.length};
}

export async function verifyGoogleLocalPaymentReadiness({databaseUrl,releaseIdentity,manifestHash,coordinatorConfigPath}) {
  const {readFile}=await import('node:fs/promises');
  const {createDatabase}=await import('../../packages/owner-identity/dist/db.js');
  const {createPostgresTaskReleaseQuerySource}=await import('../../packages/owner-identity/dist/task-store.js');
  const {db,client}=createDatabase({databaseUrl});
  try{
    const release=await createPostgresTaskReleaseQuerySource(db).getValidatedReleaseRecord(releaseIdentity,manifestHash);
    if(!release)throw new Error('google_local_payment_release_unavailable');
    const config=JSON.parse(await readFile(coordinatorConfigPath,'utf8'));
    const env=config.environments?.[0];if(!env)throw new Error('google_local_payment_environment_unavailable');
    const response=await fetch(new URL('/healthz',env.apiBaseUrl),{signal:AbortSignal.timeout(8000),redirect:'error'});
    if(!response.ok)throw new Error('google_local_payment_health_unavailable');
    return assertPaymentReadiness({manifest:release.manifest,health:await response.json(),allowedEnvironmentIds:config.environments.map(e=>e.envId)});
  }finally{await client.end()}
}
