"""Strict admitted-root family replay for BER recovery. No dispatch, scoring, or gate promotion."""
from pathlib import Path
import hashlib
from tests.bdd.adapters.ber_recovery_replay import read_reference, digest
from tests.bdd.adapters.ber_admitted_replay import normalized_command
from tests.bdd.adapters.ber_chain_effects import verify_chain_action, decode_transfer, TRANSFER

ROOT_SCHEMA='bts-admitted-actions-observation-capture/v1'
def need(v,m):
    if not v: raise AssertionError('BER generic family: '+m)
def one(rows,m):need(isinstance(rows,list) and len(rows)==1,m);return rows[0]
def doc(v):
    import json
    return json.loads(v) if isinstance(v,str) else v

def load_admitted_root(reference, *, repository_root, binding, execution, closure, task_index):
    root=Path(repository_root);packet=read_reference(root,reference)
    need(packet.get('schemaVersion')==ROOT_SCHEMA,'unsupported admitted root')
    need(packet['binding']==binding and packet['execution']==execution and packet['closure']==closure and packet['taskIndex']==task_index,'original root scope differs')
    need(set(packet['children'])=={'paid','chain'},'wrong family inventory');children={}
    for family,schema in [('paid','bts-paid-family-observation-capture/v1'),('chain','bts-chain-family-observation-capture/v1')]:
        link=packet['children'][family];child=read_reference(root,link['evidence']);need(child['schemaVersion']==schema and child['binding']==binding,'wrong family schema/binding')
        need(all(child['execution'].get(k)==v for k,v in execution.items() if k!='environmentId') and all(closure.get(k)==v for k,v in child['closure'].items()) and all(k in child['closure'] for k in ('closureId','actionCutoffSequence','reconciledActionSequence')),'child execution/closure differs')
        need(link['boundary']['actionCutoffSequence']==closure['actionCutoffSequence'],'child cutoff differs')
        session=child['bef']['session'];need(session['currentUser']==session['sessionUser']=='bef_observer' and session['transactionReadOnly']=='on' and session['transactionIsolation']=='repeatable read' and session['superuser']is False and session['bypassRls']is False,'family observer is not independent readonly')
        need(child['bef']['before']==child['bef']['after'] and digest(child['bef']['before'])==child['bef']['censusSha256'],'family census changed')
        children[family]=child
    need(all(packet['children']['paid']['boundary'][key]==packet['children']['chain']['boundary'][key] for key in ('actionCutoffSequence','baselineBlockNumber','baselineBlockHash','finalBlockNumber','finalBlockHash')),'family boundary mismatch')
    for link in packet['children'].values():need(type(link['boundary']['observationCutoffSequence']) is int and link['boundary']['observationCutoffSequence']>=0,'invalid family observation cutoff')
    return packet,children

def verify_generic_family_root(reference, owner, *, repository_root):
    """Owner has original binding/execution/closure/rows from one independent SQL snapshot."""
    root=Path(repository_root);identity=owner['observer'];need(owner['source']=='postgresql_observer' and identity['role']=='oid_observer' and identity['readOnly']is True,'owner is not readonly observer')
    binding,execution,closure=owner['binding'],owner['execution'],owner['closure'];packet,children=load_admitted_root(reference,repository_root=root,binding=binding,execution=execution,closure=closure,task_index=owner['taskIndex'])
    entries=packet['census']['entries'];rows=owner['rows'];cutoff=closure['actionCutoffSequence'];need(closure['reconciledActionSequence']==cutoff==len(entries)==len(rows) and 0<=cutoff<=256,'incomplete original cutoff')
    need(len({r['id'] for r in rows})==len(rows) and len({r['operation_id'] for r in rows})==len(rows),'duplicate original action identity');documents={}
    for sequence,(row,entry) in enumerate(zip(rows,entries),1):
        command=normalized_command(doc(row['command_json']));expected_family='read' if command['kind'].startswith('inspect_') else 'payment' if command['kind'] in ('pay','retrieve') else 'chain';need(entry['family']==expected_family,'wrong action family');need(int(row['action_sequence'])==entry['actionSequence']==sequence and command==entry['command'],'original chosen sequence/command differs')
        need(row['id']==entry['actionId'] and row['operation_id']==entry['ownerOperationId'] and row['action_kind']==entry['actionKind']==command['kind'],'action identity differs')
        need(digest({'runId':binding['runId'],'taskIndex':owner['taskIndex'],'command':command})==row['payload_hash']==entry['commandSha256'],'chosen command hash differs')
        for key,value in [('run_id',binding['runId']),('owner_id',binding['ownerId']),('agent_id',binding['agentId']),('task_id',binding['taskId']),('environment_id',binding['environmentId']),('task_index',owner['taskIndex'])]:need(row[key]==value,'original SQL action scope differs '+key)
        need(row['receipt_status']==entry['receiptStatus']=='observed' and row['receipt_revision']==entry['receiptRevision'],'original current receipt differs')
        for historical,current in [('history_revision','receipt_revision'),('history_status','receipt_status'),('history_evidence_path','evidence_path'),('history_evidence_hash','evidence_hash'),('history_transaction_hash','transaction_hash')]:need(row[historical]==row[current],'original receipt history differs')
        need(row['transaction_hash']==entry['transactionHash'] and row['evidence_path']==entry['actionEvidence']['path'] and row['evidence_hash']==entry['actionEvidence']['sha256'],'original evidence reference differs')
        actual=read_reference(root,entry['actionEvidence']);documents[entry['actionId']]=actual
        expected={'schema':'bef-task-action-observation-v1','actionId':entry['actionId'],'runId':binding['runId'],'taskIndex':owner['taskIndex'],'actionSequence':str(sequence),'ownerOperationId':entry['ownerOperationId'],'actionKind':entry['actionKind'],'commandSha256':entry['commandSha256'],'environmentId':binding['environmentId'],'generationId':execution['generationId'],'manifestSha256':execution['environmentManifestHash'],'applicationSourceSha256':execution['applicationSourceHash'],'idempotencyKey':'task-action-'+entry['actionId'],'status':'observed'}
        need(all(actual.get(k)==v for k,v in expected.items()),'retained original action lineage differs')
    paid,chain=children['paid'],children['chain'];paid_entries=[e for e in entries if e['family']!='chain'];chain_entries=[e for e in entries if e['family']=='chain']
    for actual,expected in [(paid['ownerActions'],paid_entries),(chain['externalActions'],paid_entries),(chain['ownerActions'],chain_entries)]:
        need(len(actual)==len(expected),'family partition omitted/duplicated original action')
        for a,e in zip(actual,expected):need(all(a.get(k)==e.get(k) for k in ('actionId','actionSequence','ownerOperationId','actionKind','commandSha256','transactionHash','actionEvidence')),'family partition identity differs')
    manifest=read_reference(root,chain['technicalScope']['manifest']);need(chain['technicalScope']['manifest']['sha256']==execution['environmentManifestHash'],'technical manifest pin differs')
    asset=manifest['contracts']['usdc']['address'].lower();need(one([a for a in chain['rpc']['assets'] if a['assetId']=='USDC'],'USDC missing')['address']==asset,'payment asset differs from pinned source')
    need(chain['rpc']['baseline']['blockHash']==paid['rpc']['baselineBlock']['hash'] and chain['rpc']['final']['blockHash']==paid['rpc']['finalBlock']['hash'],'RPC cohort mismatch')
    by_id={e['actionId']:e for e in entries};payments=paid['bef']['before']['payments'];deliveries=paid['bef']['before']['deliveries'];pay_count=retrieve_count=0
    for entry in paid_entries:
        kind=entry['actionKind'];actual=documents[entry['actionId']]
        operation=one([o for o in paid['bef']['before']['operations'] if o['operation_id']==actual['befOperationId']],'original paid/read operation missing')
        projected=one([a for a in paid['ownerActions'] if a['actionId']==entry['actionId']],'original family response missing');need(projected['rawResponseSha256']==actual['rawResponseSha256'],'original family response hash differs')
        if kind in ('inspect_catalog','inspect_offer'):
            need(operation['response_sha256']==actual['rawResponseSha256'],'actual read response hash differs')
            continue
        if kind=='pay':
            pay_count+=1;p=one([p for p in payments if p['transaction_hash']==entry['transactionHash']],'actual payment missing');tx=one([t for t in chain['rpc']['transactions'] if t['hash']==entry['transactionHash']],'original payment RPC missing')
            need(tx['status']==p['receipt_status']=='success' and p['operation_id']==operation['operation_id'],'actual payment not bound/settled')
            transfer=one([decode_transfer(log) for log in tx['logs'] if log['topics'][0].lower()==TRANSFER and log['address'].lower()==asset],'unique actual principal missing')
            recipient=p.get('payment_recipient') or p['facilitator_address'];need(transfer['from']==p['payer_address'] and transfer['to']==recipient and transfer['amountUnits']==p['amount_units'] and int(p['payer_balance_before'])-int(p['payer_balance_after'])==int(p['amount_units']),'payment principal/log/balance mismatch')
            cost=one([c for c in paid['bef']['before']['costs'] if c['transaction_hash']==tx['hash']],'actual gas record missing');need(int(tx['gasUsed'])*int(tx['effectiveGasPriceWei'])==int(tx['gasCostWei'])==int(cost['gas_cost_wei']) and cost['payer_role']=='facilitator' and cost['payer_address']==tx['from'],'payment gas/payer mismatch')
            prior=by_id[entry['command']['offerReadActionId']];need(prior['actionKind']=='inspect_offer' and prior['actionSequence']<entry['actionSequence'],'original offer read link invalid');offer=documents[prior['actionId']]['participantToolResponse'];first=offer['offers'][0]
            need(offer['resourceId']==entry['command']['resourceId'] and first['id']==entry['command']['offerId'] and offer['payment']==first['payment'],'selected canonical offer differs');need(first['payment']['payTo'].lower()==recipient and first['payment']['amount']==p['amount_units'] and first['payment']['asset'].lower()==asset,'payment differs from original terms')
        elif kind=='retrieve':
            import base64
            retrieve_count+=1;pay=by_id[entry['command']['payActionId']];need(pay['actionKind']=='pay' and pay['actionSequence']<entry['actionSequence'],'retrieve lacks original payment');response=actual['participantToolResponse'];data=base64.b64decode(response['contentBytes'],validate=True);need(base64.b64encode(data).decode()==response['contentBytes'] and hashlib.sha256(data).hexdigest()==response['contentHash'],'retrieved original bytes/hash differ')
            delivery=one([d for d in deliveries if d['operation_id']==actual['befOperationId']],'actual delivery row missing');need(delivery['content_sha256']==response['contentHash'] and int(delivery['byte_count'])==len(data) and delivery['resource_id']==pay['command']['resourceId']==response['resourceId'],'actual delivery SQL mismatch')
        else:need(False,'unsupported current paid kind')
    need(pay_count==len(payments) and retrieve_count==len(deliveries),'unaccounted actual paid/delivery effects')
    chain_facts=[];assets={a['assetId']:a['address'] for a in chain['rpc']['assets'] if a.get('address')}
    for entry in chain_entries:
        original=one([a for a in chain['ownerActions'] if a['actionId']==entry['actionId']],'chain action missing');tx=one([t for t in chain['rpc']['transactions'] if t['hash']==entry['transactionHash']],'chain RPC missing');chain_facts.append(verify_chain_action(entry['command'],tx,chain['rpc']['participant'],assets,chain['rpc']['routes'],original['approvalSpender']))
    # Exact per-action state/projection replay is supplied by the full matrix reader.
    # Recovery's current physical driver is single S1 pay-only, never broad chain acceptance.
    if not chain_entries:need(chain['bef']['before']['operations']==[] and chain['bef']['before']['selectedExecutions']==[] and chain['bef']['before']['selectedEvents']==[] and chain['bef']['before']['costs']==[],'unaccounted chain/setup rows require their full independent replay')
    expected_transactions={e['transactionHash'] for e in entries if e['transactionHash'] is not None}
    need(len(chain['rpc']['transactions'])==len(expected_transactions) and {t['hash'] for t in chain['rpc']['transactions']}==expected_transactions,'unaccounted RPC transaction')
    return {'root':packet,'children':children,'documents':documents,'actualPaymentCount':pay_count,'actualDeliveryCount':retrieve_count,'originalActionCount':len(entries),'chainDecoderFacts':chain_facts,'economicSubset':'paid_and_chain_requires_derived_projection' if chain_entries else 'paid_read_delivery_only','fullScenarioAcceptance':'blocked'}
