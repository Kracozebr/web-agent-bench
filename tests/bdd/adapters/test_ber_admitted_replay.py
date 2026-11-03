"""Synthetic independent-reader controls only; never physical BER acceptance."""
import copy
import json
from pathlib import Path
from uuid import uuid4
import pytest
from tests.bdd.adapters.ber_admitted_replay import KINDS,PATHS,MATRIX,digest,normalized_command,verify_census,verify_matrix,verify_admitted_learning_capture
from tests.bdd.adapters.test_mcp_call_diagnostics import reference


def control(root,mode='training',task='S1'):
    binding={**{k:str(uuid4()) for k in ('ownerId','agentId','runId')},'environmentId':'synthetic-reader-environment','releaseIdentity':'synthetic-reader-release','manifestHash':'a'*64,'caseId':'synthetic-reader-case','caseHash':'b'*64,'rubricHash':'c'*64,'taskId':task}
    execution={**{k:str(uuid4()) for k in ('preparationId','leaseId','generationId')},'environmentId':binding['environmentId'],**{k:'d'*64 for k in ('environmentManifestHash','applicationSourceHash','executionIdentityHash','initialStateSha256')}}
    closure={'closureId':str(uuid4()),'operationId':'synthetic_finish_operation','payloadHash':'e'*64,'reason':'agent_finish','actionCutoffSequence':9,'reconciledActionSequence':9}
    commands=[{'kind':'inspect_catalog'},{'kind':'inspect_offer','resourceId':'scoped_nonobjective_resource','offerId':'scoped_wrong_offer'},{'kind':'pay','resourceId':'scoped_resource','offerId':'scoped_offer','offerReadActionId':str(uuid4())},{'kind':'retrieve','payActionId':str(uuid4())},{'kind':'approve','tokenAssetId':'USDC','amountUnits':'0','gasLimit':'100000'},{'kind':'transfer','amountUnits':'1','recipient':'0x'+'1'*40,'gasLimit':'100000'},{'kind':'wrap','amountWei':'1','gasLimit':'100000'},{'kind':'unwrap','amountWei':'1','gasLimit':'100000'},{'kind':'swap','inputAssetId':'WETH','outputAssetId':'USDC','amountInUnits':'1','amountOutMinimumUnits':'0','recipient':'0x'+'2'*40,'gasLimit':'100000'}]
    rows=[];entries=[]
    for sequence,command in enumerate(commands,1):
        action_id=str(uuid4());op='synthetic_operation_'+str(sequence);payload=digest({'runId':binding['runId'],'taskIndex':0,'command':command});tx=None
        document={'schema':'bef-task-action-observation-v1','actionId':action_id,'runId':binding['runId'],'taskIndex':0,'actionSequence':str(sequence),'ownerOperationId':op,'actionKind':command['kind'],'commandSha256':payload,'environmentId':binding['environmentId'],'generationId':execution['generationId'],'manifestSha256':execution['environmentManifestHash'],'applicationSourceSha256':execution['applicationSourceHash'],'idempotencyKey':'task-action-'+action_id,'status':'observed'}
        ref=reference(root,'artifacts/runs/owner-identity-bef-task-coordinator/action/'+action_id+'.json',document)
        row={'id':action_id,'run_id':binding['runId'],'task_index':0,'owner_id':binding['ownerId'],'agent_id':binding['agentId'],'task_id':task,'environment_id':binding['environmentId'],'action_sequence':str(sequence),'operation_id':op,'payload_hash':payload,'action_kind':command['kind'],'command_json':command,'receipt_revision':1,'receipt_status':'observed','evidence_hash':ref['sha256'],'evidence_path':ref['path'],'transaction_hash':tx,'history_revision':1,'history_status':'observed','history_evidence_hash':ref['sha256'],'history_evidence_path':ref['path'],'history_transaction_hash':tx};rows.append(row)
        entries.append({'actionId':action_id,'actionSequence':sequence,'ownerOperationId':op,'actionKind':command['kind'],'command':command,'commandSha256':payload,'receiptRevision':1,'receiptStatus':'observed','transactionHash':tx,'family':'read' if command['kind'].startswith('inspect_') else 'payment' if command['kind'] in ('pay','retrieve') else 'chain','actionEvidence':{**ref,'boundary':'actual_tool_http_x402_local_evm_application_store'},'document':document})
    census={'schemaVersion':'bts-admitted-action-census/v1','classification':'identity_and_evidence_census_not_effect_proof','binding':binding,'taskIndex':0,'execution':execution,'closure':closure,'entries':entries}
    owner={'source':'postgresql_observer','observer':{'role':'oid_observer','readOnly':True,'databaseName':'synthetic_reader_only'},'mode':mode,'binding':binding,'taskIndex':0,'execution':execution,'closure':closure,'rows':rows}
    return census,owner


@pytest.mark.parametrize('mode,task',PATHS)
def test_every_current_variant_can_account_all_nine_original_kinds_without_proving_effects(tmp_path,mode,task):
    census,owner=control(tmp_path,mode,task);report=verify_census(census,owner,tmp_path)
    assert report=={'count':9,'kinds':sorted(KINDS),'identityOnly':True}


def test_census_does_not_hide_skipped_foreign_changed_or_unreconciled_rows(tmp_path):
    census,owner=control(tmp_path);verify_census(census,owner,tmp_path)
    mutations=[lambda c,o:c['entries'].pop(),lambda c,o:o['rows'].pop(),lambda c,o:o['rows'][2].update(history_revision=2),lambda c,o:o['rows'][2].update(payload_hash='f'*64),lambda c,o:o['rows'][2].update(owner_id=str(uuid4())),lambda c,o:c['entries'][4].update(family='payment'),lambda c,o:c['entries'][0].update(command={'kind':'inspect_offer','resourceId':'changed'}),lambda c,o:o['rows'][5].update(receipt_status='unknown'),lambda c,o:c['closure'].update(reconciledActionSequence=8),lambda c,o:c['entries'][0]['document'].update(generationId=str(uuid4()))]
    for mutate in mutations:
        c,o=copy.deepcopy(census),copy.deepcopy(owner);mutate(c,o)
        with pytest.raises(AssertionError):verify_census(c,o,tmp_path)
    file=tmp_path/owner['rows'][0]['evidence_path'];file.write_text('{}')
    with pytest.raises(AssertionError):verify_census(census,owner,tmp_path)


def test_matrix_requires_exact_fifteen_by_nine_and_identity_never_qualifies_effects(tmp_path):
    cells=[]
    for mode,task in PATHS:
        census,owner=control(tmp_path,mode,task);census_ref=reference(tmp_path,mode+'-'+task+'-census.json',census);owner_ref=reference(tmp_path,mode+'-'+task+'-owner.json',owner)
        cells.extend({'mode':mode,'taskId':task,'kind':kind,'censusRef':census_ref,'ownerSnapshotRef':owner_ref} for kind in KINDS)
    assert len(MATRIX)==135 and len(verify_matrix(cells,tmp_path))==135
    for changed in (cells[:-1],cells+[cells[0]],[{**cells[0],'mode':'training','taskId':'S3'},*cells[1:]]):
        with pytest.raises(AssertionError):verify_matrix(changed,tmp_path)
    source=tmp_path/'synthetic-pinned-source.txt';source.write_text('reader-only control');import hashlib
    pinned={'synthetic-pinned-source.txt':hashlib.sha256(source.read_bytes()).hexdigest()}
    capture={'schemaVersion':'ber-admitted-learning-identity-capture/v1','sourceInputs':{'before':pinned,'after':pinned},'cells':cells,'status':'passed','allEffectsVerified':True}
    ref=reference(tmp_path,'identity-only.json',capture);report=verify_admitted_learning_capture(ref,'BER-SC-009',repository_root=tmp_path)
    assert report['identityCells']==135 and report['fullScenarioAcceptance']=='blocked' and report['facts']=={} and report['missingBoundaries']
    source.write_text('drift')
    with pytest.raises(AssertionError):verify_admitted_learning_capture(ref,'BER-SC-009',repository_root=tmp_path)


def test_command_contract_keeps_references_and_optional_defaults_without_repair():
    assert normalized_command({'kind':'approve','amountUnits':'0','gasLimit':'1'})['tokenAssetId']=='WETH'
    for c in ({'kind':'purchase','resourceId':'x','offerId':'y'},{'kind':'inspect_catalog','arbitrary':True},{'kind':'pay','resourceId':'x','offerId':'y','offerReadActionId':'invented'},{'kind':'transfer','amountUnits':'-1','recipient':'0x'+'1'*40,'gasLimit':'1'}):
        with pytest.raises(AssertionError):normalized_command(c)
