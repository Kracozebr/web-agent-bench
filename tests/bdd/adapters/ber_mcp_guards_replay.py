"""Independent finite MCP denial/replay proof, joined to original owner census."""
from tests.bdd.adapters.ber_matrix_common import need,one

EXPECTED={0:{'protocol_disabled_purchase':'COMBINED_PURCHASE_UNAVAILABLE','fabricated_offer_read':'TASK_PAYMENT_REFERENCE_UNAVAILABLE','fabricated_payment':'TASK_PAYMENT_REFERENCE_UNAVAILABLE','after_closure_new_action_not_deadline_test':'TASK_CLOSED'},1:{'foreign_task_offer_read':'TASK_PAYMENT_REFERENCE_UNAVAILABLE','foreign_task_payment':'TASK_PAYMENT_REFERENCE_UNAVAILABLE','after_closure_new_action_not_deadline_test':'TASK_CLOSED'},2:{'after_closure_new_action_not_deadline_test':'TASK_CLOSED'}}

def verify_guard_call(record,calls,*,error=None):
 i=record['callIndex'];need(type(i)is int and 0<=i<len(calls),'guard call index absent');call=calls[i]
 need(call['tool']==record['tool'] and call['args']==record['arguments'] and call['bodySha256']==record['bodySha256'],'guard record differs from actual SDK call')
 if error:need(call['isError'] is True and call['body'].get('error',{}).get('code')==error and record['actualCode']==record['expectedCode']==error and not call['body'].get('admitted') and not call['body'].get('actionId'),'guard is not actual precise no-admission error')
 else:need(call['isError'] is False and not call['body'].get('error'),'replay is not a successful original SDK call')
 return call

def verify_mcp_guards(owner,actor):
 m=actor['berMatrix'];need(m['mode']=='training' and m['profile']=='MCP_GUARDS' and actor['taskIds']==['S1','M1','H1'] and len(m['tasks'])==3,'guard exact Training scope required');calls=m['calls'];allops={a['operation_id'] for a in owner['actions']};denied=set();count=0;s1=None
 for index,task in enumerate(m['tasks']):
  proof=task['mcpGuards'];need(proof['schemaVersion']=='ber-controlled-mcp-guards-task/v1' and proof['positiveCoverageCredit'] is False,'guard cannot contribute positive cells');rows=sorted([r for r in owner['actions'] if r['task_index']==index],key=lambda r:int(r['action_sequence']));need([r['action_kind'] for r in rows]==['inspect_catalog','inspect_offer','pay','retrieve'],'guard admits an unexpected extra effect')
  refs=proof['originalRefs'];need(refs['runId']==actor['runId'] and refs['offerReadActionId']==rows[1]['id'] and refs['payActionId']==rows[2]['id'],'guard references not original actual actions')
  variants=[d['variant'] for d in proof['denials']];need(len(set(variants))==len(variants) and set(variants)==set(EXPECTED[index]),'missing/duplicate finite guard case')
  for rec in proof['denials']:
   name=rec['variant'];call=verify_guard_call(rec,calls,error=EXPECTED[index][name]);args=call['args'];need(args['runId']==actor['runId'] and args['taskIndex']==index and args['operationId'] not in allops and args['operationId'] not in denied,'denied call admitted or operation identity reused');denied.add(args['operationId']);command=args['command']
   if name=='protocol_disabled_purchase':need(command=={'kind':'purchase','resourceId':refs['resourceId'],'offerId':refs['offerId']},'disabled protocol request differs')
   elif name in ('fabricated_offer_read','foreign_task_offer_read'):
    need(command['kind']=='pay' and command['offerReadActionId'] not in {r['id'] for r in rows},'invalid-reference case uses a valid current reference')
    if name.startswith('foreign'):need(s1 and command['offerReadActionId']==s1['offerReadActionId'] and proof['foreignTaskRefs']==s1,'foreign offer reference is not real preceding-task handle')
    else:need(command['offerReadActionId'] not in {r['id'] for r in owner['actions']},'fabricated reference is an actual admitted action')
   elif name in ('fabricated_payment','foreign_task_payment'):
    need(command['kind']=='retrieve' and command['payActionId'] not in {r['id'] for r in rows},'invalid payment reference is valid in this task')
    if name.startswith('foreign'):need(s1 and command['payActionId']==s1['payActionId'],'foreign pay reference is not real preceding-task payment')
    else:need(command['payActionId'] not in {r['id'] for r in owner['actions']},'fabricated payment is actual')
   else:need(command=={'kind':'inspect_catalog'},'postclosure action differs')
   count+=1
  repeats=proof['repeats'];need(len(repeats)==2 and {r['variant'] for r in repeats}=={'same_original_payment_status','same_original_finish'},'original status/finish replay missing')
  for rec in repeats:
   call=verify_guard_call(rec,calls);body=call['body'];args=call['args']
   if rec['variant']=='same_original_payment_status':
    r=rows[2];need(call['tool']=='runs.task_action_status' and args=={'runId':actor['runId'],'actionId':r['id']} and body['actionId']==r['id'] and body['transactionHash']==r['transaction_hash'] and body['status']==r['receipt_status'] and body['receiptRevision']==r['receipt_revision'] and body['evidencePath']==r['evidence_path'] and body['evidenceHash']==r['evidence_hash'],'status replay changed original effect/evidence')
   else:
    closure=one([c for c in owner['closures'] if c['task_index']==index],'one original closure');need(call['tool']=='runs.finish_task' and args['runId']==actor['runId'] and args['taskIndex']==index and args['operationId']==closure['operation_id'] and body['closureId']==closure['id'] and body['reason']=='agent_finish' and body['replayed'] is True,'finish replay changed original cutoff')
  if index==0:s1=refs
 return {'actualDeniedCalls':count,'originalStatusReplays':3,'originalFinishReplays':3,'unchangedFourActionCensusPerTask':True,'deniedOperationsAbsentFromOwnerAdmissions':True,'postClosureIsNotTaskDeadlineProof':True,'positiveCoverageCredit':False}
