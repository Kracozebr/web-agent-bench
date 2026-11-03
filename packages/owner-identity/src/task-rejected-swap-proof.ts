/** AICODE-NOTE: A deterministic EOA guard denial is a fact only with the original source census and an independent historical code read. HTTP status alone is never no-execution proof. */
import {createHash} from 'node:crypto';
import {keccak256,type Hex} from 'viem';
import {canonicalTaskJson} from './task-release.js';
import {TaskActionCommandSchema} from './task-action-service.js';
type J=Record<string,unknown>;
const rec=(v:unknown):v is J=>!!v&&typeof v==='object'&&!Array.isArray(v);
const exact=(v:J,keys:string[])=>Object.keys(v).sort().join('\0')===keys.sort().join('\0');
const same=(a:unknown,b:unknown)=>canonicalTaskJson(a)===canonicalTaskJson(b);
const hash=(v:unknown)=>createHash('sha256').update(canonicalTaskJson(v)).digest('hex');
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digest=/^[0-9a-f]{64}$/,tx=/^0x[0-9a-f]{64}$/,address=/^0x[0-9a-f]{40}$/;
function need(v:unknown):asserts v {if(!v)throw new Error('rejected_swap_proof_invalid');}
export type RejectedRecipientCode={schemaVersion:'bef-selected-recipient-code-observation/v1';environmentId:string;generationId:string;operationId:string;requestSha256:string;recipient:string;blockNumber:string;blockHash:string;code:Hex;codeKeccak256:Hex};
export type RejectedSwapGuardMarker={schemaVersion:'bef-selected-recipient-code-guard/v1';reasonCode:'selected_recipient_must_be_eoa';operationId:string;requestSha256:string};
export function validateRejectedRecipientCode(value:unknown):RejectedRecipientCode {
 need(rec(value)&&exact(value,['schemaVersion','environmentId','generationId','operationId','requestSha256','recipient','blockNumber','blockHash','code','codeKeccak256']));
 need(value.schemaVersion==='bef-selected-recipient-code-observation/v1'&&typeof value.environmentId==='string'&&/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value.environmentId)&&uuid.test(String(value.generationId))&&uuid.test(String(value.operationId))&&digest.test(String(value.requestSha256))&&address.test(String(value.recipient))&&/^(?:0|[1-9][0-9]{0,77})$/.test(String(value.blockNumber))&&tx.test(String(value.blockHash))&&typeof value.code==='string'&&/^0x(?:[0-9a-f]{2})+$/.test(value.code)&&Buffer.byteLength(canonicalTaskJson(value))<=4*1024*1024&&tx.test(String(value.codeKeccak256))&&keccak256(value.code as Hex)===value.codeKeccak256);
 return value as RejectedRecipientCode;
}
export function rejectedSwapGuardMarkerMatches(value:unknown,operationId:unknown):boolean {
 return rec(value)&&exact(value,['schemaVersion','reasonCode','operationId','requestSha256'])&&value.schemaVersion==='bef-selected-recipient-code-guard/v1'&&value.reasonCode==='selected_recipient_must_be_eoa'&&value.operationId===operationId&&uuid.test(String(operationId))&&digest.test(String(value.requestSha256));
}
/** Read-only historical verification; this port cannot sign, submit or reconcile a transaction. */
export async function rereadRejectedRecipientCode(value:unknown,request:(method:string,params:readonly unknown[])=>Promise<unknown>):Promise<RejectedRecipientCode>{
 const guard=validateRejectedRecipientCode(value),tag=`0x${BigInt(guard.blockNumber).toString(16)}`;
 const first=await request('eth_getBlockByNumber',[tag,false]);const code=await request('eth_getCode',[guard.recipient,tag]);const last=await request('eth_getBlockByNumber',[tag,false]);
 need(rec(first)&&rec(last)&&first.number===tag&&last.number===tag&&first.hash===guard.blockHash&&last.hash===first.hash&&code===guard.code);
 return validateRejectedRecipientCode({...guard,code});
}
export function rejectedSwapSource(input:{action:J;source:unknown;environmentId:string;generationId:string;participantId:unknown;environmentManifest:Uint8Array;environmentManifestSha256:string;assets:Array<{assetId:string;address:string|null}>;contracts:Array<{address:string;codeHash:string}>;routes:Array<{tokenInAssetId:string;tokenOutAssetId:string;feeTier:number;router:string;pool:string}>}):RejectedRecipientCode {
 const {action,environmentId,generationId}=input,parsed=TaskActionCommandSchema.safeParse(action.command);need(parsed.success&&parsed.data.kind==='swap');const c=parsed.data;
 const source=input.source;need(rec(source)&&exact(source,['operation','selectedExecution','selectedEvents','costsCount','paymentsCount','deliveriesCount'])&&source.costsCount===0&&source.paymentsCount==='0'&&source.deliveriesCount==='0'&&rec(source.operation)&&rec(source.selectedExecution)&&Array.isArray(source.selectedEvents)&&source.selectedEvents.length===2);
 const op=source.operation,s=source.selectedExecution;
 need(exact(op,['operationId','environmentId','generationId','participantId','idempotencyKeySha256','requestSha256','actionKind','status','receiptStatus','transactionHash','responseSha256','startedAt','completedAt'])&&exact(s,['operationId','environmentId','generationId','actionKind','selectedAction','prestate','transactionIntent','measurement','transactionHash','outcome','reasonCode','completedAt']));
 const selected={kind:'swap',inputAssetId:c.inputAssetId,outputAssetId:c.outputAssetId,feeTier:c.feeTier??500,amountInUnits:c.amountInUnits,amountOutMinimumUnits:c.amountOutMinimumUnits,recipient:c.recipient.toLowerCase(),gasLimit:c.gasLimit};
 const route=input.routes.find(r=>r.tokenInAssetId===c.inputAssetId&&r.tokenOutAssetId===c.outputAssetId&&r.feeTier===(c.feeTier??500));need(route);
 const tokenIn=input.assets.find(a=>a.assetId===c.inputAssetId)?.address,tokenOut=input.assets.find(a=>a.assetId===c.outputAssetId)?.address;need(tokenIn&&tokenOut);
 // AICODE-NOTE: Preserve the pinned producer's checksum/hash spelling in request hashes; semantic address equality alone cannot reconstruct immutable historical request bytes.
 need(input.environmentManifest.byteLength>0&&input.environmentManifest.byteLength<=256*1024&&createHash('sha256').update(input.environmentManifest).digest('hex')===input.environmentManifestSha256);
 const manifest:unknown=JSON.parse(Buffer.from(input.environmentManifest).toString('utf8'));need(rec(manifest)&&rec(manifest.contracts));const pins=manifest.contracts;
 const router=pins.swapRouter02,from=pins[c.inputAssetId==='WETH'?'weth':'usdc'],to=pins[c.outputAssetId==='WETH'?'weth':'usdc'];need(rec(router)&&rec(from)&&rec(to)&&typeof router.address==='string'&&typeof from.address==='string'&&typeof to.address==='string'&&router.address.toLowerCase()===route.router.toLowerCase()&&from.address.toLowerCase()===tokenIn.toLowerCase()&&to.address.toLowerCase()===tokenOut.toLowerCase());
 const pool=Object.values(pins).find(p=>rec(p)&&typeof p.address==='string'&&p.address.toLowerCase()===route.pool.toLowerCase());
 const base={kind:'swap',route:'uniswap-v3-exactInputSingle',router:router.address,tokenIn:from.address,tokenOut:to.address,fee:route.feeTier};
 const legacy=route.feeTier===500&&c.inputAssetId==='WETH'&&c.outputAssetId==='USDC';
 if(legacy)need(rec(manifest.swap)&&typeof manifest.swap.tokenIn==='string'&&typeof manifest.swap.tokenOut==='string'&&manifest.swap.tokenIn.toLowerCase()===tokenIn.toLowerCase()&&manifest.swap.tokenOut.toLowerCase()===tokenOut.toLowerCase()&&manifest.swap.fee===500);
 if(route.feeTier===3000)need(rec(pool)&&typeof pool.address==='string'&&typeof pool.codeHash==='string'&&pool.fee===3000&&input.contracts.some(p=>p.address.toLowerCase()===route.pool.toLowerCase()&&p.codeHash.replace(/^0x/,'').toLowerCase()===(pool.codeHash as string).replace(/^0x/,'').toLowerCase()));
 const swap=rec(manifest.swap)?manifest.swap:{};
 const actionRequest=legacy?{...base,tokenIn:swap.tokenIn,tokenOut:swap.tokenOut,amountInWei:c.amountInUnits,amountOutMinimumUsdcUnits:c.amountOutMinimumUnits,recipient:c.recipient.toLowerCase(),gasLimit:c.gasLimit}:{...base,inputAssetId:c.inputAssetId,outputAssetId:c.outputAssetId,...(route.feeTier===3000&&rec(pool)?{poolAddress:pool.address,poolCodeHash:pool.codeHash}:{}),amountInUnits:c.amountInUnits,amountOutMinimumUnits:c.amountOutMinimumUnits,recipient:c.recipient.toLowerCase(),gasLimit:c.gasLimit};
 const requestSha256=hash({method:'POST',path:'/tools/swap',action:actionRequest});
 need(rejectedSwapGuardMarkerMatches(action.rejectionProof,action.befOperationId)&&rec(action.rejectionProof)&&action.rejectionProof.requestSha256===requestSha256);
 need(op.operationId===action.befOperationId&&uuid.test(String(op.operationId))&&op.environmentId===environmentId&&op.generationId===generationId&&op.participantId===input.participantId&&op.idempotencyKeySha256===createHash('sha256').update(`task-action-${String(action.actionId)}`).digest('hex')&&op.requestSha256===requestSha256&&op.actionKind==='swap'&&op.status==='rejected'&&op.receiptStatus==='not_submitted'&&op.transactionHash===null&&op.responseSha256===null&&typeof op.startedAt==='string'&&typeof op.completedAt==='string'&&Number.isFinite(Date.parse(op.startedAt))&&Number.isFinite(Date.parse(op.completedAt))&&Date.parse(op.completedAt)>=Date.parse(op.startedAt));
 need(s.operationId===op.operationId&&s.environmentId===environmentId&&s.generationId===generationId&&s.actionKind==='swap'&&same(s.selectedAction,selected)&&s.prestate===null&&s.transactionIntent===null&&s.measurement===null&&s.transactionHash===null&&s.outcome==='rejected'&&s.reasonCode==='selected_recipient_must_be_eoa'&&typeof s.completedAt==='string'&&Number.isFinite(Date.parse(s.completedAt)));
 const events=source.selectedEvents;need(events.every(rec));const first=events[0]!,last=events[1]!;
 need(rec(last.eventPayload)&&exact(last.eventPayload,['reasonCode','recipientCodeObservation'])&&last.eventPayload.reasonCode==='selected_recipient_must_be_eoa');const guard=validateRejectedRecipientCode(last.eventPayload.recipientCodeObservation);
 need(guard.environmentId===environmentId&&guard.generationId===generationId&&guard.operationId===op.operationId&&guard.requestSha256===requestSha256&&guard.recipient===selected.recipient);
 const ids=new Set<string>(),sequences=new Set<string>();for(const [index,event] of events.entries()){
  need(exact(event,['eventId','eventSequence','operationId','eventKind','eventJsonSha256','transactionHash','eventPayload'])&&uuid.test(String(event.eventId))&&!ids.has(String(event.eventId))&&/^[1-9][0-9]*$/.test(String(event.eventSequence))&&!sequences.has(String(event.eventSequence))&&event.operationId===op.operationId&&event.eventKind===(index===0?'selected_action_bound':'rejected_before_broadcast')&&event.transactionHash===null&&event.eventJsonSha256===hash(event.eventPayload));ids.add(String(event.eventId));sequences.add(String(event.eventSequence));
 }
 need(BigInt(String(last.eventSequence))>BigInt(String(first.eventSequence))&&same(first.eventPayload,{actionKind:'swap',selectedAction:selected,requestSha256}));return guard;
}
