/** Actual owner UI -> native OAuth -> selected connection launch. Disposable acceptance only. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import pg from 'pg';
import {createCard} from './credential-cases.mjs';
import {issueAndRedeemBonusCodeForWorker} from './bonus-code-cases.mjs';
import {validateAndActivatePinnedRelease,quoteTrainingSelectionUnits,setS1FinancialPolicyThroughOwnerUi} from './genuine-s1-cases.mjs';
import {runAgentClientConnectionOwnerCase as runNativeConnection,consentAciNativeAuthorization} from './agent-client-connection-cases.mjs';
import {assertSecretFree} from './evidence.mjs';

const fingerprint=value=>createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
function canonical(value){if(Array.isArray(value))return value.map(canonical);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));return value;}
const usdc=units=>`${units/1000000n}.${(units%1000000n).toString().padStart(6,'0')}`;
const endpoint=(response,path,method)=>new URL(response.url()).pathname===path&&response.request().method()===method;
const uuid=value=>/^[a-f0-9-]{36}$/.test(value??'');

/** SQL returns hashes instead of private task/action or provider payloads. No mutations. */
export async function observeAgentClientConnection(pool,{ownerId,agentId,stage}){
  const client=await pool.connect();
  try{
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const database=(await client.query("SELECT current_user AS role,current_database() AS \"databaseName\",current_setting('transaction_read_only') AS \"transactionReadOnly\"")).rows[0];
    assert.equal(database.role,'oid_observer');assert.equal(database.transactionReadOnly,'on');assert.match(database.databaseName,/^oid_acceptance_[a-f0-9]{32}$/);
    const policy=(await client.query('SELECT p.training,p.ranked,p.forum_messages AS "forumMessages",p.custom_topics AS "customTopics" FROM oid_agent_policy p JOIN oid_agent a ON a.id=p.agent_id WHERE p.agent_id=$1 AND a.owner_id=$2',[agentId,ownerId])).rows[0];
    const financialRow=(await client.query('SELECT revision,allow_cash_shortfall,operation_limit_units::text,utc_day_limit_units::text,category_limits FROM oid_agent_financial_policy WHERE agent_id=$1 AND owner_id=$2',[agentId,ownerId])).rows[0];
    const financialPolicyRevision=financialRow?.revision;
    const caps=financialRow?{allow_cash_shortfall:financialRow.allow_cash_shortfall,operation_limit_units:financialRow.operation_limit_units,utc_day_limit_units:financialRow.utc_day_limit_units,category_limits:financialRow.category_limits}:undefined;
    const grants=(await client.query(`SELECT g.id::text,g.owner_id::text,g.agent_id::text,g.oauth_client_id AS client_id,g.resource,g.source,g.access_generation,g.revoked_at,g.expires_at,
      p.created_at AS last_preflight_at,p.metadata->>'protocolVersion' AS protocol_version
      FROM oid_agent_access_grant g LEFT JOIN LATERAL(SELECT created_at,metadata FROM oid_audit
        WHERE event_type='agent.connection.preflight' AND actor_owner_id=g.owner_id AND metadata->>'connectionId'=g.id::text ORDER BY created_at DESC,id DESC LIMIT 1)p ON true
      WHERE g.owner_id=$1 AND g.agent_id=$2 ORDER BY g.created_at,g.id`,[ownerId,agentId])).rows.map(row=>({...row,permissions_hash:fingerprint(policy),caps_hash:fingerprint(caps)}));
    const intents=(await client.query('SELECT id::text,owner_id::text,agent_id::text,status,run_id::text FROM oid_run_launch_intent WHERE owner_id=$1 AND agent_id=$2 ORDER BY created_at,id',[ownerId,agentId])).rows;
    const bindings=(await client.query(`SELECT metadata->>'intentId' AS intent_id,metadata->>'connectionId' AS connection_id FROM oid_audit
      WHERE event_type='agent.connection.intent_bound' AND actor_owner_id=$1 AND metadata->>'agentId'=$2 ORDER BY created_at,id`,[ownerId,agentId])).rows;
    const runs=(await client.query('SELECT id::text,intent_id::text,owner_id::text,agent_id::text,status,mode FROM oid_benchmark_run WHERE owner_id=$1 AND agent_id=$2 ORDER BY queued_at,id',[ownerId,agentId])).rows;
    const domainQueries={
      runs:'SELECT * FROM oid_benchmark_run WHERE owner_id=$1 AND agent_id=$2',
      queue:"SELECT * FROM oid_benchmark_run WHERE owner_id=$1 AND agent_id=$2 AND status='queued'",
      reservations:'SELECT x.* FROM oid_run_reservation x JOIN oid_benchmark_run r ON r.id=x.run_id WHERE r.owner_id=$1 AND r.agent_id=$2',
      ledger:'SELECT * FROM oid_ledger_entry WHERE owner_id=$1 AND $2::uuid IS NOT NULL',
      taskActions:'SELECT * FROM oid_run_task_action WHERE owner_id=$1 AND agent_id=$2',
      publications:'SELECT agent_id AS id,* FROM oid_agent_first_public_action WHERE owner_id=$1 AND agent_id=$2',
    };
    const domainDigests={};for(const [name,query]of Object.entries(domainQueries)){
      const row=(await client.query(`SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.id)::text,'[]'),'UTF8')),'hex') AS digest FROM (${query})x`,[ownerId,agentId])).rows[0];domainDigests[name]=row.digest;
    }
    const runIds=runs.map(x=>x.id),reservations=(await client.query('SELECT count(DISTINCT run_id)::int AS logical_count,count(*)::int AS lot_count,COALESCE(sum(amount_units),0)::text AS units FROM oid_run_reservation WHERE run_id=ANY($1::uuid[])',[runIds])).rows[0];
    const debits=(await client.query("SELECT count(DISTINCT operation_id)::int AS logical_count,count(*)::int AS lot_count,COALESCE(sum(amount_units),0)::text AS units FROM oid_ledger_entry WHERE owner_id=$1 AND entry_type='debit' AND operation_id=ANY($2::text[])",[ownerId,runIds.map(id=>'rundeb_'+id.replaceAll('-',''))])).rows[0];
    const tasks=(await client.query('SELECT run_id::text,task_index,task_id,status,closure_reason FROM oid_run_task WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,task_index',[runIds])).rows;
    const evaluations=(await client.query('SELECT run_id::text,task_index,task_id,input_hash,result_hash,result_json->>\'status\' AS status FROM oid_run_task_evaluation WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,task_index',[runIds])).rows;
    await client.query('COMMIT');return JSON.parse(JSON.stringify({stage,database,policy,caps,financialPolicyRevision,grants,intents,bindings,runs,domainDigests,admission:{reservationCount:Number(reservations.logical_count),reservationLotCount:Number(reservations.lot_count),reservationUnits:reservations.units,debitCount:Number(debits.logical_count),debitLotCount:Number(debits.lot_count),debitUnits:debits.units},tasks,evaluations}));
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
}

/** Exact consent display conversion only; no grant, permission or policy writes. */
export function consentLimitUnits(value){
  if(value===null)return null;
  assert.equal(typeof value,'string');assert(value.length<=80&&/^(0|[1-9][0-9]*)\.[0-9]{6}$/.test(value),'invalid exact consent limit');
  const [whole,fraction]=value.split('.');return (BigInt(whole)*1000000n+BigInt(fraction)).toString();
}
export function consentLimitDisplay(value){const units=consentLimitUnits(value);return units===null?'Unlimited by this policy limit':`${value} USDC / ${units} micro-USDC`;}
export function normalizeConsentFinancialPolicy(policy){
  assert(policy&&policy.token==='USDC'&&policy.precision===6&&typeof policy.allowCashShortfall==='boolean');
  assert(Number.isSafeInteger(policy.revision)&&policy.revision>=0&&typeof policy.configured==='boolean');
  assert.deepEqual(Object.keys(policy.categoryLimits).sort(),['benchmark','forum']);
  consentLimitUnits(policy.categoryLimits.benchmark);consentLimitUnits(policy.categoryLimits.forum);
  return {allow_cash_shortfall:policy.allowCashShortfall,operation_limit_units:consentLimitUnits(policy.operationLimit),utc_day_limit_units:consentLimitUnits(policy.utcDayLimit),category_limits:{benchmark:policy.categoryLimits.benchmark,forum:policy.categoryLimits.forum}};
}

export async function approveAgentClientConsent({ownerPage,agentId,ownerId,setup,authorizationUrl,callbackUri,onStage=()=>{},onDiagnostic=()=>{},readFinancialPolicySnapshot}){
  let evidence,failedPage;
  const diagnostic={schemaVersion:'aci-native-consent-diagnostic/v1',step:'navigation',network:[]};
  const step=name=>{diagnostic.step=name;onStage('consent_'+name);};
  const knownEndpoints=new Set(['/api/auth/oauth2/authorize','/api/owner/agents/oauth-select','/api/owner/agents/oauth-consent-context','/api/owner/agents/oauth-consent','/api/owner']);
  const knownPages=new Set(['/agents','/owner/agents/oauth-select','/owner/agents/oauth-consent','/sign-in','/api/auth/error']);
  const pageState=()=>{try{const path=new URL(ownerPage.url()).pathname;return {lastPagePathname:knownPages.has(path)?path:null,unknownPage:!knownPages.has(path)};}catch{return {lastPagePathname:null,unknownPage:true};}};
  const observeResponse=response=>{try{const url=new URL(response.url()),status=response.status(),method=response.request().method();if(url.origin===new URL(setup.resource).origin&&knownEndpoints.has(url.pathname)&&Number.isInteger(status)&&status>=100&&status<=599&&['GET','POST'].includes(method)&&diagnostic.network.length<32)diagnostic.network.push({pathname:url.pathname,method,status});}catch{/* No arbitrary exception data is retained. */}};
  ownerPage.on?.('response',observeResponse);
  try{
  step('navigation');
  const callbackUrl=await consentAciNativeAuthorization({ownerPage,authorizationUrl,callbackUri,selectAndApprove:async page=>{
    try{
    step('selector_wait');const select=page.getByTestId('oauth-consent-agent-select');await select.waitFor({state:'visible',timeout:15000});
    step('agent_selection');await select.selectOption(agentId);
    const contextPromise=page.waitForResponse(response=>endpoint(response,'/api/owner/agents/oauth-consent-context','POST'));
    void contextPromise.catch(()=>{}); // Still await the original promise; early HTTP denial must not leave an unhandled rejection.
    const selectedPromise=page.waitForResponse(response=>endpoint(response,'/api/owner/agents/oauth-select','POST'));
    void selectedPromise.catch(()=>{});
    step('continue_click');await page.getByTestId('oauth-agent-continue').click();step('continue_http');const selected=await selectedPromise;diagnostic.continueHttpStatus=selected.status();assert.equal(selected.status(),200);
    step('context_http');const contextResponse=await contextPromise;diagnostic.contextHttpStatus=contextResponse.status();assert.equal(contextResponse.status(),200);const context=await contextResponse.json();
    step('context_binding');
    assert.equal(context.agent.id,agentId);assert.equal(context.client.clientId,setup.clientId);assert.equal(context.resource,setup.resource);assert.equal(context.redirectUri,callbackUri);
    assert.deepEqual([...context.scopes].sort(),['agent:operate','offline_access']);
    step('displayed_context');await page.getByTestId('oauth-consent-context').waitFor({state:'visible',timeout:15000});
    assert.equal((await page.getByTestId('oauth-consent-client-id').innerText()).trim(),setup.clientId);
    assert.equal((await page.getByTestId('oauth-consent-resource').innerText()).trim(),setup.resource);
    step('displayed_permissions');const permissions={};for(const [key,suffix]of Object.entries({training:'training',ranked:'ranked',forumMessages:'forum-messages',customTopics:'custom-topics'})){
      const item=page.getByTestId('oauth-consent-permission-'+suffix),text=(await item.innerText()).trim().toLowerCase();
      permissions[key]=/\b(?:enabled|allowed|on)\b/.test(text)&&!/\b(?:disabled|not allowed|off)\b/.test(text);
      assert.equal(permissions[key],context.agent.permissions[key]);
    }
    step('displayed_financial_policy');
    assert.equal(typeof readFinancialPolicySnapshot,'function');
    const financialContext={revision:context.financialPolicy?.revision,configured:context.financialPolicy?.configured,allowCashShortfall:context.financialPolicy?.allowCashShortfall,operationLimit:context.financialPolicy?.operationLimit,utcDayLimit:context.financialPolicy?.utcDayLimit,categoryLimits:context.financialPolicy?.categoryLimits,token:context.financialPolicy?.token,precision:context.financialPolicy?.precision};
    const displayedFinancialPolicy=normalizeConsentFinancialPolicy(financialContext),displayedFinancialText={};
    await page.getByTestId('oauth-consent-financial-policy').waitFor({state:'visible',timeout:15000});
    for(const [key,testId,value]of [['operation','oauth-consent-operation-limit',financialContext.operationLimit],['day','oauth-consent-day-limit',financialContext.utcDayLimit],['benchmark','oauth-consent-category-benchmark',financialContext.categoryLimits.benchmark],['forum','oauth-consent-category-forum',financialContext.categoryLimits.forum]]){
      displayedFinancialText[key]=(await page.getByTestId(testId).innerText()).trim();assert.equal(displayedFinancialText[key],consentLimitDisplay(value));
    }
    displayedFinancialText.cash=(await page.getByTestId('oauth-consent-cash-shortfall').innerText()).trim();
    assert.equal(displayedFinancialText.cash,financialContext.allowCashShortfall?'Allowed by the current owner policy':'Not allowed by the current owner policy');
    const snapshot=await readFinancialPolicySnapshot();
    assert.equal(snapshot.ownerId,ownerId);assert.equal(snapshot.agentId,agentId);assert.equal(snapshot.database.role,'oid_observer');assert.equal(snapshot.database.transactionReadOnly,'on');
    assert.deepEqual(displayedFinancialPolicy,snapshot.caps);assert.equal(financialContext.revision,snapshot.financialPolicyRevision);
    const financialPolicySnapshot={database:snapshot.database,ownerId,agentId,caps:snapshot.caps,financialPolicyRevision:snapshot.financialPolicyRevision};
    const displayedFinancialFingerprint=fingerprint(displayedFinancialPolicy);
    const decided=page.waitForResponse(response=>endpoint(response,'/api/owner/agents/oauth-consent','POST'));
    void decided.catch(()=>{});
    step('approve_click');await page.getByTestId('oauth-consent-approve').click();step('approve_http');const response=await decided;diagnostic.decisionHttpStatus=response.status();assert.equal(response.status(),200);
    evidence={clicked:true,ownerId,agentId,clientId:setup.clientId,resource:setup.resource,redirectUri:callbackUri,scopes:['agent:operate','offline_access'],displayedPermissionFingerprint:fingerprint(permissions),financialContext,displayedFinancialPolicy,displayedFinancialText,displayedFinancialFingerprint,financialPolicySnapshot,continueHttpStatus:200,decisionHttpStatus:response.status(),flowId:context.flowId};
    step('callback_wait');
    }catch(error){failedPage=pageState();throw error;}
  }});
  step('callback_confirmed');onDiagnostic({...diagnostic,status:'completed',...pageState()});return {callbackUrl,evidence};
  }catch(error){
    const safe={...diagnostic,status:'blocked',reasonCode:'aci_consent_'+diagnostic.step+'_failed',errorClass:['TimeoutError','AssertionError','Error','TypeError'].includes(error?.name)?error.name:'Error',...(failedPage??pageState())};
    onDiagnostic(safe);throw new Error('aci_native_consent_failed');
  }finally{ownerPage.off?.('response',observeResponse);}
}

export async function runAgentClientConnectionOwnerCase(input){
  const base={...input.commonCapture?.genuineCaptureInput,...input},captureId=base.captureId??input.commonCapture?.runId;
  assert.equal(base.publicOrigin,'http://127.0.0.1:3000');assert(uuid(captureId));assert(uuid(base.ownerId));
  assert.equal(typeof base.restartConnectionRegistration,'function');
  const pool=new pg.Pool({connectionString:base.observerDatabaseUrl,max:2,application_name:'aci-independent-readonly-observer'});
  let ownerPage=base.ownerPage,adminPage=base.adminPage,agentId,registrationObservation,consentDiagnostic;
  const stages=[];let phase='release_activation';
  const stage=name=>{phase=name;if(stages.length<64)stages.push({name,at:new Date().toISOString()});};
  try{
    stage('release_activation');
    const release=base.validatedRelease??await validateAndActivatePinnedRelease({repositoryRoot:base.repoRoot,databaseUrl:base.databaseUrl,observerDatabaseUrl:base.observerDatabaseUrl});
    const taskIds=base.aciTaskIds??['S1'];assert.deepEqual(taskIds,['S1']);const units=quoteTrainingSelectionUnits(release,taskIds);
    stage('bonus_code_funding_ui');const funding=await issueAndRedeemBonusCodeForWorker({adminPage,ownerPage,adminCapture:base.adminCapture,ownerCapture:base.ownerCapture,ownerId:base.ownerId,observerDatabaseUrl:base.observerDatabaseUrl,label:'Native OAuth smoke '+captureId.slice(0,8),amount:usdc(units),amountUnits:units.toString()});
    stage('agent_create_ui');
    await ownerPage.goto('/agents',{waitUntil:'domcontentloaded'});const card=await createCard(ownerPage,'Native OAuth '+captureId.slice(0,8),base.ownerCapture);agentId=card.id;
    const panel=ownerPage.getByTestId('agent-card-'+agentId);await panel.waitFor({state:'visible'});
    stage('agent_permission_ui');await panel.getByTestId('agent-permission-training').check();const permissionSaved=ownerPage.waitForResponse(response=>endpoint(response,`/api/owner/agents/${agentId}/permissions`,'PUT'));await panel.getByTestId('agent-permissions-save').click();assert.equal((await permissionSaved).status(),200);
    stage('financial_policy_ui');
    const financialPolicy=await setS1FinancialPolicyThroughOwnerUi({ownerPage,observerPool:pool,ownerId:base.ownerId,agentId,limitUnits:units});
    stage('connection_setup_ui');const connections=panel.getByTestId('agent-connections-'+agentId);await connections.getByLabel('Remote MCP URL').waitFor({state:'visible'});
    const setupResponse=await ownerPage.request.get(`/api/owner/agents/${agentId}/connections`);assert.equal(setupResponse.status(),200);const configuration=await setupResponse.json();
    const publicClient=configuration.clientRegistrations.find(x=>x.clientId===(base.aciClientId??'oid-local-mcp-client'));assert(publicClient);
    const setup={serverUrl:configuration.serverUrl,resource:configuration.resource,clientId:publicClient.clientId,development:true};
    assert.equal(await connections.getByLabel('Remote MCP URL').inputValue(),setup.serverUrl);
    const checked=ownerPage.waitForResponse(response=>endpoint(response,`/api/owner/agents/${agentId}/connections`,'GET'));await connections.getByRole('button',{name:'Check connection',exact:true}).click();assert.equal((await checked).status(),200);
    const result=await runNativeConnection({repoRoot:base.repoRoot,captureId,setup,onStage:stage,
      setupBrowser:{clicked:true,displayedEndpoint:setup.serverUrl,delivery:'url_fallback',addLink:null},
      onNativeRegistration:async registration=>{
        const receipt=await base.restartConnectionRegistration({connectionRegistration:{clientId:registration.clientId,redirectUri:registration.callbackUri}});
        if(receipt?.ownerPage)ownerPage=receipt.ownerPage;if(receipt?.adminPage)adminPage=receipt.adminPage;
        const response=await ownerPage.request.get(`/api/owner/agents/${agentId}/connections`);assert.equal(response.status(),200);const active=await response.json();
        const configured=active.clientRegistrations.find(item=>item.clientId===registration.clientId);assert(configured?.redirectUris?.includes(registration.callbackUri));
        registrationObservation={clientId:registration.clientId,callbackUri:registration.callbackUri,configurationHttpStatus:response.status(),configuredRedirectUris:configured.redirectUris,
          restartReceipt:receipt?Object.fromEntries(['schemaVersion','startedAt','finishedAt','previousPid','currentPid','healthHttpStatus','boundary'].filter(key=>receipt[key]!==undefined).map(key=>[key,receipt[key]])):null};
      },
      onAuthorizationUrl:args=>approveAgentClientConsent({ownerPage,agentId,ownerId:base.ownerId,setup,...args,onStage:stage,onDiagnostic:value=>{consentDiagnostic=value;},readFinancialPolicySnapshot:async()=>({...await observeAgentClientConnection(pool,{ownerId:base.ownerId,agentId,stage:'consent_financial_snapshot'}),ownerId:base.ownerId,agentId})}),
      observeReadonly:stage=>observeAgentClientConnection(pool,{ownerId:base.ownerId,agentId,stage}),
      readMcpProjections:async()=>{
        const text=await readFile(resolve(base.repoRoot,'artifacts/runs/agent-client-connection',captureId,'mcp-projections.jsonl'),'utf8');return text.trim().split('\n').filter(Boolean).map(x=>JSON.parse(x));
      },
      onBrowserLaunch:async({connection})=>{
        const grant=connection.grants.find(x=>x.source==='oauth'&&x.client_id===setup.clientId&&x.revoked_at===null);assert(grant);
        await ownerPage.context().grantPermissions(['clipboard-read','clipboard-write'],{origin:base.publicOrigin});
        await ownerPage.goto('/runs?agentId='+agentId,{waitUntil:'domcontentloaded'});await ownerPage.getByTestId('run-agent-select').selectOption(agentId);await ownerPage.getByTestId('run-mode-select').selectOption('training');
        await ownerPage.getByTestId('run-connection-select').selectOption(grant.id);
        assert.equal(await ownerPage.getByTestId('run-legacy-connection').isChecked(),false);
        for(const taskId of ['S1','M1','H1']){const checkbox=ownerPage.getByTestId('run-task-checkbox-'+taskId);if(taskIds.includes(taskId))await checkbox.check();else await checkbox.uncheck();}
        const responsePromise=ownerPage.waitForResponse(response=>endpoint(response,'/api/owner/runs/intents','POST'));await ownerPage.getByTestId('run-intent-create').click();const response=await responsePromise;assert([200,201].includes(response.status()));const body=await response.json(),request=response.request().postDataJSON();
        const intentId=body.intent.id;assert(uuid(intentId));assert.equal(request.selectedConnectionId,grant.id);assert.equal(request.agentId,agentId);assert.deepEqual(request.taskIds,taskIds);
        const visible=await ownerPage.getByTestId('run-intent-handoff-text-'+intentId).innerText(),copy=ownerPage.getByTestId('run-intent-handoff-'+intentId);await copy.click();await copy.filter({hasText:'Copied safe handoff'}).waitFor({state:'visible'});
        const clipboard=await ownerPage.evaluate(()=>navigator.clipboard.readText());assert.equal(clipboard,visible);
        return {clicked:true,ownerId:base.ownerId,agentId,intentId,selectedConnectionId:grant.id,handoffPrompt:clipboard,httpStatus:response.status(),taskIds,quotePriceUnits:units.toString(),delivery:{kind:'clipboard_fallback',siteStartActionCount:1,copyActionCount:1,pasteActionCount:1,nativeSendActionCount:1,twoActionClaim:false}};
      },
    });
    result.aci.ownerId=base.ownerId;result.aci.agentId=agentId;result.aci.registrationObservation=registrationObservation;result.aci.ownerSetup={card,financialPolicy,funding,releaseIdentity:release.releaseIdentity,taskIds};result.aci.stages=stages;result.aci.phase=phase;
    if(consentDiagnostic){result.aci.consentDiagnostic=consentDiagnostic;if(consentDiagnostic.status==='blocked')result.aci.blocker=consentDiagnostic.reasonCode;}
    assertSecretFree(result,'aci-owner-native-partial');return result;
  }catch{
    // Never retain assertion messages, Playwright URLs, provider bodies or thrown properties.
    return {status:'blocked',aci:{schemaVersion:'agent-client-connection-physical-capture/v1',captureId,status:'blocked',qualificationScope:'local_loopback_development_only',ownerId:base.ownerId,...(uuid(agentId)?{agentId}:{}),phase,stages,...(consentDiagnostic?{consentDiagnostic}:{}),blocker:'aci_'+phase+'_failed',nativeTurns:[]}};
  }finally{await pool.end();}
}
