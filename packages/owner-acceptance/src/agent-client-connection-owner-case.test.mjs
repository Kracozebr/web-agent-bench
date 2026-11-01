import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {approveAgentClientConsent,runAgentClientConnectionOwnerCase,normalizeConsentFinancialPolicy,consentLimitUnits,consentLimitDisplay} from './agent-client-connection-owner-case.mjs';
function ownerFixture({wrongAgent=false}={}){
  const ownerId=randomUUID(),agentId=randomUUID(),flowId=randomUUID(),setup={clientId:'unit_public',resource:'http://127.0.0.1:3000/api/agent/mcp'},callbackUri='http://127.0.0.1:38765/callback/native_id';
  const context={flowId,redirectUri:callbackUri,client:{clientId:setup.clientId},resource:setup.resource,scopes:['offline_access','agent:operate'],agent:{id:wrongAgent?randomUUID():agentId,permissions:{training:true,ranked:false,forumMessages:false,customTopics:false}}};
  context.financialPolicy={revision:1,configured:true,allowCashShortfall:false,operationLimit:'0.083334',utcDayLimit:'0.083334',categoryLimits:{benchmark:'0.083334',forum:'0.000000'},token:'USDC',precision:6};
  const actions=[];let callbackHandler,responseIndex=0;
  const responses=[{path:'/api/owner/agents/oauth-consent-context',body:context},{path:'/api/owner/agents/oauth-select',body:{}},{path:'/api/owner/agents/oauth-consent',body:{}}];
  const page={
    async route(pattern,handler){callbackHandler=handler;actions.push('exact_callback_route');assert.equal(pattern,callbackUri+'**');},
    async unroute(){actions.push('callback_route_removed');},
    async goto(url){actions.push(new URL(url).pathname==='/agents'?'safe_owner_page_restored':'real_authorization_navigation');},
    async waitForResponse(predicate){const response=responses[responseIndex++],out={url:()=>`http://127.0.0.1:3000${response.path}`,request:()=>({method:()=> 'POST'}),status:()=>200,json:async()=>response.body};assert.equal(predicate(out),true);return out;},
    getByTestId(id){return {
      async waitFor(){},
      async selectOption(value){assert.equal(id,'oauth-consent-agent-select');assert.equal(value,agentId);actions.push('selected_exact_agent');},
      async innerText(){if(id==='oauth-consent-client-id')return setup.clientId;if(id==='oauth-consent-resource')return setup.resource;if(id==='oauth-consent-cash-shortfall')return 'Not allowed by the current owner policy';if(['oauth-consent-operation-limit','oauth-consent-day-limit','oauth-consent-category-benchmark','oauth-consent-category-forum'].includes(id))return consentLimitDisplay(id==='oauth-consent-category-forum'?'0.000000':'0.083334');return id==='oauth-consent-permission-training'?'Allowed':'Not allowed';},
      async click(){actions.push(id);if(id==='oauth-consent-approve')await callbackHandler({request:()=>({url:()=>callbackUri+'?code=synthetic-unit-code&state=synthetic-unit-state'}),abort:async()=>actions.push('actual_redirect_intercepted'),continue:async()=>assert.fail('unexpected callback forwarding')});},
    };},
  };
  return {ownerPage:page,ownerId,agentId,setup,callbackUri,authorizationUrl:'http://127.0.0.1:3000/api/auth/oauth2/authorize?state=synthetic-unit-state',actions,readFinancialPolicySnapshot:async()=>({ownerId,agentId,database:{role:'oid_observer',databaseName:'oid_acceptance_'+'a'.repeat(32),transactionReadOnly:'on'},caps:normalizeConsentFinancialPolicy(context.financialPolicy),financialPolicyRevision:1})};
}
test('ACI real consent callback contract selects exact owner agent, inspects displayed permissions and keeps callback private',async()=>{
  const fixture=ownerFixture();const result=await approveAgentClientConsent(fixture);
  assert.equal(result.callbackUrl,fixture.callbackUri+'?code=synthetic-unit-code&state=synthetic-unit-state');
  assert.equal(result.evidence.agentId,fixture.agentId);assert.equal(result.evidence.ownerId,fixture.ownerId);assert.deepEqual(result.evidence.scopes,['agent:operate','offline_access']);
  assert.equal(JSON.stringify(result.evidence).includes('synthetic-unit-code'),false);assert.equal(JSON.stringify(result.evidence).includes('synthetic-unit-state'),false);
  assert(fixture.actions.indexOf('selected_exact_agent')<fixture.actions.indexOf('oauth-consent-approve'));assert.equal(fixture.actions.at(-1),'safe_owner_page_restored');
});
test('ACI consent refuses mismatched server-selected agent before approval and restores safe page',async()=>{
  const fixture=ownerFixture({wrongAgent:true});await assert.rejects(approveAgentClientConsent(fixture));
  assert.equal(fixture.actions.includes('oauth-consent-approve'),false);assert.equal(fixture.actions.at(-1),'safe_owner_page_restored');
});
test('ACI wrapper retains a fixed failed-stage diagnostic without raw assertion/provider URL or thrown properties',async()=>{
  const captureId=randomUUID(),ownerId=randomUUID();
  const result=await runAgentClientConnectionOwnerCase({captureId,ownerId,publicOrigin:'http://127.0.0.1:3000',observerDatabaseUrl:'postgres://unused@127.0.0.1:1/unused',restartConnectionRegistration:async()=>{},validatedRelease:{trainingTasks:{map(){throw Object.assign(new Error('provider.example/callback?code=PRIVATE_CANARY&state=PRIVATE_CANARY'),{rawProviderBody:'PRIVATE_CANARY'});}},trainingPriceUnits:'1'}});
  assert.equal(result.status,'blocked');assert.equal(result.aci.phase,'release_activation');assert.equal(result.aci.blocker,'aci_release_activation_failed');
  assert.deepEqual(result.aci.stages.map(x=>x.name),['release_activation']);assert.equal(JSON.stringify(result).includes('PRIVATE_CANARY'),false);
});
test('ACI selector timeout retains only known HTTP path/status and pre-restoration page, never OAuth query/body',async()=>{
  for(const unknownPage of [false,true]){
    const fixture=ownerFixture(),page=fixture.ownerPage,originalLocator=page.getByTestId.bind(page);let listener,diagnostic,current='http://127.0.0.1:3000/agents';const stages=[];
    page.url=()=>current;page.on=(event,callback)=>{assert.equal(event,'response');listener=callback;};page.off=()=>{listener=null;};
    page.goto=async url=>{
      if(new URL(url).pathname==='/agents'){current=url;return;}
      current='http://127.0.0.1:3000/'+(unknownPage?'private/SECRET_CANARY':'api/auth/error')+'?code=SECRET_CANARY&state=SECRET_CANARY';
      listener({url:()=> 'http://127.0.0.1:3000/api/auth/oauth2/authorize?state=SECRET_CANARY',status:()=>400,request:()=>({method:()=> 'GET'})});
    };
    page.getByTestId=id=>id==='oauth-consent-agent-select'?{waitFor:async()=>{const error=new Error('Raw callback?code=SECRET_CANARY&state=SECRET_CANARY');error.name='TimeoutError';throw error;}}:originalLocator(id);
    await assert.rejects(approveAgentClientConsent({...fixture,onStage:value=>stages.push(value),onDiagnostic:value=>{diagnostic=value;}}),error=>error.message==='aci_native_consent_failed');
    assert.equal(diagnostic.step,'selector_wait');assert.equal(diagnostic.errorClass,'TimeoutError');assert.equal(diagnostic.reasonCode,'aci_consent_selector_wait_failed');
    assert.deepEqual(diagnostic.network,[{pathname:'/api/auth/oauth2/authorize',method:'GET',status:400}]);
    assert.equal(diagnostic.lastPagePathname,unknownPage?null:'/api/auth/error');assert.equal(diagnostic.unknownPage,unknownPage);assert.equal(JSON.stringify(diagnostic).includes('SECRET_CANARY'),false);
    assert.deepEqual(stages,['consent_navigation','consent_selector_wait']);assert.equal(listener,null);assert.equal(new URL(current).pathname,'/agents');
  }
});

test('ACI consent financial normalization preserves BigInt precision and fails closed on malformed limits',()=>{
  assert.equal(consentLimitUnits('9007199254740993.123456'),'9007199254740993123456');assert.equal(consentLimitUnits(null),null);assert.equal(consentLimitDisplay('0.083334'),'0.083334 USDC / 83334 micro-USDC');
  for(const value of ['0.08','1e6','-0.000001','00.000001','1.0000001',0.1,undefined])assert.throws(()=>consentLimitUnits(value));
});
test('ACI financial context never substitutes for a foreign or changed authoritative policy snapshot',async()=>{
  const fixture=ownerFixture(),read=fixture.readFinancialPolicySnapshot;
  await assert.rejects(approveAgentClientConsent({...fixture,readFinancialPolicySnapshot:async()=>({...await read(),agentId:randomUUID()})}),error=>error.message==='aci_native_consent_failed');
  assert.equal(fixture.actions.includes('oauth-consent-approve'),false);
});
