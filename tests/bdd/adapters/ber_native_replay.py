"""Actual native process, diagnostic trace and original durable run linkage."""
import hashlib,re
from urllib.parse import urlparse,parse_qs
from pathlib import Path
from tests.bdd.adapters.ber_matrix_common import need,one,load_ref,digest
from tests.bdd.adapters.ber_recovery_replay import read_reference,verify_native_recovery_history,_epoch

UUID=re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$');HASH=re.compile(r'^[a-f0-9]{64}$')

def verify_native_action_causality(native,diagnostics,packet,client_outbox):
 run=one(packet['rows']['run'],'one native run');case=one([c for c in diagnostics['cases'] if c['runId']==run['id']],'one bound diagnostic case')
 need(diagnostics['source']=='postgresql_observer' and diagnostics['observer']['role']=='oid_observer' and diagnostics['observer']['readOnly'] is True,'native diagnostic observer authority absent')
 need(native['implementation']=='native_codex_cli' and native['boundary']=='actual_pinned_native_model_process' and native['localToolCalls']==[],'native process boundary missing or local tools used')
 need(native['clientVersion'] in ('0.165.0','0.166.0'),'unqualified native client profile');summary=native['summary'];need(summary['exitCode']==0 and summary['interrupted'] is False and summary['terminalEvent']=='turn.completed','native process did not end cleanly');need(all(summary[k]==0 for k in ('localToolCallCount','unknownMcpToolCallCount','skippedOversizeLines','unparsedJsonLines')),'native event census incomplete or foreign tools observed')
 selection=native['selection'];need(selection['intentId']==case['intentId']==run['intent_id'] and selection['agentId']==case['agentId']==run['agent_id'] and selection['mode']==run['mode'] and case['ownerId']==run['owner_id'],'native selection/diagnostic case/owner differs')
 calls=native['calls'];need(client_outbox['calls']==calls,'native call projection differs from actual own SQLite event rows');need(summary['mcpToolCallCount']==len(calls),'native summary/call census omitted observations');need(calls and all(c['server']=='w3bench_user' and c['type'] in ('mcp_tool_call','mcp_tool_call_end') and HASH.fullmatch(c['callIdHash']) for c in calls),'native tool census absent or contains another server');need(len({c['callIdHash'] for c in calls})==len(calls),'native call identities duplicated')
 terminal=[c for c in calls if c.get('tool')=='runs.current_task' and c.get('outcome')=='success' and c.get('run',{}).get('runId')==run['id'] and c['run'].get('terminal') is True and c['run'].get('status')=='completed'];need(terminal,'native did not observe explicit completed terminal')
 events=[e for e in diagnostics['events'] if e['caseId']==case['caseId'] and e.get('source')=='server'];links=[]
 for action in packet['rows']['actions']:
  op_sha=hashlib.sha256(action['operation_id'].encode()).hexdigest();sdk=[e for e in events if e.get('stage')=='sdk_validation' and e.get('tool')=='runs.task_action' and e.get('operationIdHash')==op_sha and e.get('outcome')=='success' and UUID.fullmatch(str(e.get('traceId',''))) and HASH.fullmatch(str(e.get('callIdHash','')))];matched=[]
  for trace in sdk:
   call=[c for c in calls if c['tool']=='runs.task_action' and UUID.fullmatch(str(c.get('traceId',''))) and c['traceId']==trace['traceId']]
   admission=[e for e in events if e.get('stage')=='admission' and e.get('outcome')=='success' and e.get('traceId')==trace.get('traceId') and e.get('actionId')==action['id'] and e.get('taskIndex')==action['task_index']]
   if call and admission:
    for c in call:
     observed=[e for e in client_outbox['events'] if e.get('eventId')==c['eventId'] and e.get('source')=='client' and e.get('tool')==c['tool'] and e.get('callIdHash')==c['callIdHash'] and e.get('traceId')==c['traceId'] and e.get('operationIdHash')==op_sha]
     if len(observed)==1:matched.append((trace,[c],admission))
  need(matched,'owner action lacks native call/SDK operation hash/admission trace join');links.append({'actionId':action['id'],'operationIdHash':op_sha,'traceId':matched[0][0]['traceId'],'nativeCallIdHash':matched[0][1][0]['callIdHash'],'wireCallIdHash':matched[0][0]['callIdHash']})
 return {'runId':run['id'],'mode':run['mode'],'nativeAdmissionLinks':links,'actualNativeToolCalls':len(calls),'actualTerminalCallIdHash':terminal[-1]['callIdHash'],'localToolCalls':0}

def verify_native_ui(ui,packet,repo):
 run=one(packet['rows']['run'],'one native run');url=urlparse(ui['runUrl']);need(url.scheme in ('http','https') and url.path=='/runs' and not url.username and not url.password and ('agentId' not in parse_qs(url.query) or parse_qs(url.query)['agentId']==[run['agent_id']]),'native UI route/agent differs');need(ui['source']=='actual_browser_observer' and ui['runId']==run['id'] and ui['mode']==run['mode'] ,'UI belongs to another native run')
 read_reference(repo,ui['screenshotRef'],json_body=False);dom=load_ref(repo,ui['domSnapshotRef']);need(dom['runId']==run['id'] and dom['runStatus']=='completed','actual rendered native run not completed')
 expected=[{'taskId':e['task_id'],'outcome':e['result_json']['outcome'],'credit':e['result_json']['credit']} for e in sorted(packet['rows']['evaluations'],key=lambda x:x['task_index'])]
 need(ui['renderedTasks']==dom['taskRows']==expected,'actual rendered grades differ from persisted evaluator')
 launch=load_ref(repo,ui['intentActionRef']);need(launch['source']=='actual_browser_observer' and launch['action']=='click' and launch['intentId']==run['intent_id'] and launch['agentId']==run['agent_id'] and launch['mode']==run['mode'] and launch['taskIds']==run['task_ids'],'browser-created intent differs from accepted original run')
 before=load_ref(repo,launch['beforeDomRef']);after=load_ref(repo,launch['afterDomRef']);need(run['intent_id'] not in before['visibleIntentIds'] and run['intent_id'] in after['visibleIntentIds'] and after['agentId']==run['agent_id'] and after['mode']==run['mode'] and after['taskIds']==run['task_ids'],'actual click DOM selection/result does not bind new accepted intent')
 return {'runId':run['id'],'mode':run['mode'],'actualBrowserIntentAndResultsMatchDurableRun':True}

def verify_native_receipt(native,diagnostics,outbox,transport):
 need(outbox['source']=='sqlite_observer' and outbox['observer']=={'role':'client_sqlite_observer','readOnly':True},'native own outbox readonly observer absent');case=outbox['case'];need(all(UUID.fullmatch(str(case.get(k,''))) for k in ('caseId','diagnosticSessionId')),'native case/report identity invalid');server=one([c for c in diagnostics['cases'] if c['caseId']==case['caseId']],'canonical native case absent');need(case['diagnosticSessionId']==server['diagnosticSessionId'] and case['intentId']==server['intentId']==native['selection']['intentId'] and case['state']=='synced','native outbox is pending, foreign or unbound')
 receipt=transport['body'];segment=receipt['segmentId'];need(UUID.fullmatch(str(segment)),'native actual receipt segment missing');expected='/api/diagnostics/cases/'+case['caseId']+'/receipt?segmentId='+segment;need(transport['source']=='http_transport' and transport['method']=='GET' and transport['path']==expected and transport['httpStatus']==200 and receipt['caseId']==case['caseId'],'actual own helper HTTP receipt not retained')
 reports=[r for r in diagnostics['reports'] if r['caseId']==case['caseId']];server_events=[e for e in diagnostics['events'] if e['caseId']==case['caseId']];errors=sum(e.get('outcome')=='error' for e in server_events);need(type(server['errorCount'])is int and server['errorCount']==errors,'actual diagnostic error counter differs from retained events');clean=errors==0 and case['gap']==0 and server['captureState']=='complete' and receipt['completion']=='complete' and not any(e.get('outcome')=='error' for e in outbox['events'])
 if clean:
  need(not reports and case['reportId'] is None and server['reportId'] is None and receipt['reportId'] is None and receipt['reportCreated'] is False,'clean complete diagnostics must not invent an error report');report_id=None
 else:
  report=one(reports,'canonical diagnostic error report missing or duplicated');need(UUID.fullmatch(str(receipt['reportId'])) and report['id']==case['reportId']==server['reportId']==receipt['reportId'] and report['ownerId']==server['ownerId'] and receipt['reportCreated'] is True,'native error/partial report pointer differs');report_id=report['id']
 batches=sorted([b for b in diagnostics['batches'] if b['caseId']==case['caseId'] and b['segmentId']==segment],key=lambda b:b['batchSequence']);local=sorted([b for b in outbox['batches'] if b['segmentId']==segment],key=lambda b:b['batchSequence']);need(local and len(batches)==len(local),'native local/SQL batch inventory differs')
 for index,(l,b) in enumerate(zip(local,batches)):
  need(set(l)=={'segmentId','batchSequence','events','completion','payloadHash'} and l['batchSequence']==b['batchSequence']==index and l['payloadHash']==b['payloadHash']==digest({k:v for k,v in l.items() if k!='payloadHash'}) and l['completion']==b['completion'],'native original batch bytes/watermark differ')
 events=[e for b in local for e in b['events']];need(len({e['eventId'] for e in events})==len(events) and {e['eventId']:e for e in events}=={e['eventId']:e for e in outbox['events']},'native final batches omitted/duplicated original client envelopes')
 for e in events:
  actual=one([s for s in diagnostics['events'] if s['caseId']==case['caseId'] and s['eventId']==e['eventId']],'uploaded original client envelope absent');need(all(actual.get(k)==v for k,v in e.items()),'native uploaded envelope differs from original spool')
 need(receipt['diagnosticsSynced'] is True and receipt['highestContiguousSequence']==len(local)-1 and receipt['highestContiguousHash']==local[-1]['payloadHash'] and receipt['completion']==local[-1]['completion'] and receipt['completion'] in ('complete','partial'),'native actual HTTP ACK has gap or no final declaration')
 if receipt['completion']=='partial':need(server['captureState'] in ('partial','partial_quota'),'partial native capture falsely claims complete')
 return {'caseId':case['caseId'],'reportId':report_id,'actualHttpReceiptVerified':True,'contiguousBatches':len(local),'captureCompletion':receipt['completion'],'caseCaptureState':server['captureState'],'diagnosticsSynced':True,'cleanNoErrorReport':clean}


def verify_native_connection(connection,packet,diagnostics,ui):
 need(connection['source']=='postgresql_observer' and connection['observer']['role']=='oid_observer' and connection['observer']['readOnly'] is True,'OAuth authority is not actual readonly SQL');run=packet['rows']['run'][0];case=one([c for c in diagnostics['cases'] if c['runId']==run['id']],'one native diagnostic case');grant=one(connection['rows'],'one actual native grant')
 allowed={'id','owner_id','agent_id','source','role','resource','oauth_client_id','access_generation','created_at','expires_at','revoked_at'};need(set(grant)==allowed,'OAuth proof contains unexpected/sensitive grant columns');url=urlparse(ui['runUrl']);need(grant['id']==case['connectionId'] and grant['owner_id']==run['owner_id'] and grant['agent_id']==run['agent_id'] and grant['source']=='oauth' and grant['role']=='agent' and grant['resource']==url.scheme+'://'+url.netloc+'/api/agent/mcp' and isinstance(grant['oauth_client_id'],str) and grant['oauth_client_id'],'actual native grant is foreign/manual/wrong resource')
 need(type(grant['access_generation'])is int and grant['access_generation']>0,'invalid native grant generation')
 for a in packet['rows']['actions']:
  t=_epoch(a['accepted_at']);need(a['grant_id']==grant['id'] and a['access_generation']==grant['access_generation'] and _epoch(grant['created_at'])<=t<_epoch(grant['expires_at']) and (grant['revoked_at'] is None or t<_epoch(grant['revoked_at'])),'native action not admitted through original valid OAuth generation')
 return {'connectionId':grant['id'],'source':'oauth','role':'agent','resource':grant['resource'],'accessGeneration':grant['access_generation'],'secretColumnsRetained':False}


def verify_native_runs(items,repo):
 need(isinstance(items,list) and len(items)==2,'actual native Training and Ranked selectors required');seen=set();reports=[]
 for item in items:
  need(set(item)=={'nativeRef','diagnosticsRef','historyRef','uiRef','clientOutboxRef','receiptRef','connectionRef'},'native selector must contain exact original references')
  native=load_ref(repo,item['nativeRef']);diagnostics=load_ref(repo,item['diagnosticsRef']);history=load_ref(repo,item['historyRef']);need(len(history['runs'])==1,'native history must bind one run');packet=history['runs'][0];mode=packet['rows']['run'][0]['mode'];need(mode in ('training','ranked') and mode not in seen,'duplicate/foreign native mode');seen.add(mode)
  outbox=load_ref(repo,item['clientOutboxRef']);need(diagnostics['observer']['databaseName']==history['databaseName'],'native diagnostics/history databases differ');durable=verify_native_recovery_history(item['historyRef'],repository_root=repo,required_modes=[mode]);linked=verify_native_action_causality(native,diagnostics,packet,outbox);ui_raw=load_ref(repo,item['uiRef']);ui=verify_native_ui(ui_raw,packet,repo);connection_raw=load_ref(repo,item['connectionRef']);need(connection_raw['observer']['databaseName']==history['databaseName'],'native OAuth authority database differs');authority=verify_native_connection(connection_raw,packet,diagnostics,ui_raw);receipt=verify_native_receipt(native,diagnostics,outbox,load_ref(repo,item['receiptRef']));reports.append({'mode':mode,'durable':durable,'causalNativeAdmissions':linked,'UI':ui,'OAuthAuthority':authority,'diagnosticReceipt':receipt})
 need(seen=={'training','ranked'},'missing native mode');return {'actualNativeTrainingAndRanked':True,'runs':reports,'SDKReferenceSubstituted':False,'rubricRescored':False}
