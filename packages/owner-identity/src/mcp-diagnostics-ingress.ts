import { createHash, randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { DIAGNOSTIC_TOOLS, DIAGNOSTIC_ERROR_CODES, DIAGNOSTIC_FIELD_PATHS, canonicalDiagnosticJson, type DiagnosticEnvelope } from './mcp-diagnostics-contract.js';
import { recordServerDiagnostic, type DiagnosticDependencies, type DiagnosticPrincipal } from './mcp-diagnostics-service.js';
import { withDiagnosticRequest, setDiagnosticActionSink, captureDiagnosticWork, type DiagnosticBoundary } from './mcp-diagnostics-boundary.js';
import { sql } from 'drizzle-orm';
import { HttpError } from './http-error.js';
import { z } from 'zod';
import { deriveDiagnosticPolicyEvidence } from './mcp-diagnostics-policy-evidence.js';
import { decodeDiagnosticWire, attachDiagnosticMetadata } from './mcp-diagnostics-wire.js';
import type { OwnerDatabase } from './db.js';

const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
const object=(value:unknown):Record<string,unknown>=>value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,unknown>:{};
interface Ingress { traceId:string; startedAt:Date; principal?:DiagnosticPrincipal; handlerEntered:boolean; captureAvailable:boolean;
  schemaHash?:string;contractHash?:string;fieldPaths?:DiagnosticEnvelope['fieldPaths'];failureStage?:DiagnosticEnvelope['stage'];
  authStartedAt?:Date;authCompletedAt?:Date;sdkStartedAt?:Date;handlerStartedAt?:Date;handlerCompletedAt?:Date;receiptStartedAt?:Date }

// AICODE-NOTE: Project only registered fields. Never persist JSON-RPC arguments,
// text responses, bearer headers or error messages, including validation messages.
export function diagnosticResponseCode(value:unknown,httpStatus:number) {
  const rpc=object(value),result=object(rpc.result),structured=object(result.structuredContent);
  const rpcError=object(rpc.error);
  const candidates=[rpcError.code,object(rpcError.data).code,object(structured.error).code,structured.code];
  for(const item of candidates)if(typeof item==='string'&&(DIAGNOSTIC_ERROR_CODES as readonly string[]).includes(item))return item as typeof DIAGNOSTIC_ERROR_CODES[number];
  // Tool error content is decoded in memory, then reduced to a registered code.
  if(result.isError===true&&Array.isArray(result.content))for(const item of result.content.slice(0,8)){
    const text=object(item).text;
    if(typeof text==='string'&&Buffer.byteLength(text)<=65536)try{
      const parsed=object(JSON.parse(text)),code=object(parsed.error).code??parsed.code;
      if(typeof code==='string'&&(DIAGNOSTIC_ERROR_CODES as readonly string[]).includes(code))return code as typeof DIAGNOSTIC_ERROR_CODES[number];
    }catch{/* Unregistered text is never retained. */}
  }
  if(rpcError.code===-32602)return 'INPUT_VALIDATION_ERROR';
  if([-32700,-32600,-32601].includes(Number(rpcError.code)))return 'INVALID_ARGUMENTS';
  if(['FST_ERR_CTP_INVALID_JSON_BODY','FST_ERR_CTP_EMPTY_JSON_BODY'].includes(String(rpc.code)))return 'INVALID_ARGUMENTS';
  if(httpStatus===401)return 'UNAUTHORIZED';
  if(httpStatus===403)return 'FORBIDDEN';
  if(httpStatus===429)return 'RATE_LIMITED';
  return rpc.error||result.isError===true||httpStatus>=400?'UNKNOWN_ERROR':undefined;
}

export function registerDiagnosticIngress(app:FastifyInstance,deps:DiagnosticDependencies,
  options:{actionDb?:OwnerDatabase;authorizationDb?:OwnerDatabase}={}) {
  const contexts=new WeakMap<FastifyRequest,Ingress>();
  setDiagnosticActionSink(options.actionDb??deps.db,async boundary=>{
    if(!boundary.actionId||!UUID.test(boundary.actionId))return;
    const rows=await deps.db.execute(sql`SELECT c.id AS case_id,c.owner_id,c.agent_id,c.connection_id,a.task_index,
      COALESCE(o.delivered_at,a.accepted_at) AS started_at,
      CASE WHEN ${boundary.stage}='receipt' THEN rcp.updated_at ELSE o.delivered_at END AS completed_at,
      (SELECT e.trace_id FROM oid_mcp_diagnostic_event e WHERE e.case_id=c.id AND e.stage='admission'
       AND e.envelope->>'actionId'=a.id::text ORDER BY e.created_at,e.event_id LIMIT 1) AS trace_id
      FROM oid_run_task_action a JOIN oid_benchmark_run r ON r.id=a.run_id
      JOIN oid_run_task_action_outbox o ON o.action_id=a.id JOIN oid_run_task_action_receipt rcp ON rcp.action_id=a.id
      JOIN oid_mcp_diagnostic_case c ON c.intent_id=r.intent_id AND c.owner_id=a.owner_id
        AND c.agent_id=a.agent_id AND c.connection_id=a.grant_id WHERE a.id=${boundary.actionId}::uuid`) as unknown as
      Array<{case_id:string;owner_id:string;agent_id:string;connection_id:string;task_index:number;trace_id:string|null;started_at:Date|string;completed_at:Date|string|null}>;
    for(const row of rows){
      if(!row.completed_at&&!(boundary.outcome==='error'&&boundary.completedAt))continue;
      const started=new Date(boundary.startedAt??row.started_at),completed=new Date(boundary.completedAt??row.completed_at!),digest=hash(`${row.case_id}:${boundary.stage}:${boundary.actionId}:${boundary.receiptRevision??0}`);
      const eventId=boundary.attemptId&&UUID.test(boundary.attemptId)?boundary.attemptId:
        `${digest.slice(0,8)}-${digest.slice(8,12)}-8${digest.slice(13,16)}-a${digest.slice(17,20)}-${digest.slice(20,32)}`;
      // A dispatch claim is unknown until a durable executor receipt proves its outcome.
      await recordServerDiagnostic(deps,{caseId:row.case_id,principal:{ownerId:row.owner_id,agentId:row.agent_id,connectionId:row.connection_id},
        event:{eventId,source:'server',tool:'runs.task_action',stage:boundary.stage,outcome:boundary.outcome,
          startedAt:started.toISOString(),completedAt:completed.toISOString(),durationMs:Math.max(0,completed.getTime()-started.getTime()),actionId:boundary.actionId,taskIndex:row.task_index,
          ...(row.trace_id?{traceId:row.trace_id}:{}),...(boundary.errorCode?{errorCode:boundary.errorCode}:{})}});
    }
  });
  app.addHook('onRequest',async request=>{
    if(request.url.split('?',1)[0]!=='/api/agent/mcp')return;
    // Clock only: never perform unmetered authentication or database work
    // before the route's normal IP limiter. Durable outcome follows onSend.
    contexts.set(request,{traceId:randomUUID(),startedAt:new Date(),handlerEntered:false,captureAvailable:true});
  });
  app.addHook('onSend',async(request,reply,payload)=>{
    const context=contexts.get(request);if(!context)return payload;
    const completedAt=new Date(),body=object(request.body),params=object(body.params),args=object(params.arguments);
    const tool=(DIAGNOSTIC_TOOLS as readonly unknown[]).includes(params.name)?params.name as DiagnosticEnvelope['tool']:'unknown';
    const wire=typeof payload==='string'||Buffer.isBuffer(payload)?decodeDiagnosticWire(payload,String(reply.getHeader('content-type')??'')):undefined;
    const response=wire?.messages.find(message=>message.jsonrpc==='2.0'&&(message.id===body.id||body.id===undefined&&message.id===null&&message.error))??
      (reply.statusCode>=400?wire?.messages.find(message=>message.jsonrpc===undefined):undefined)??{};
    const recognized=Object.keys(response).length>0;
    const noResponseExpected=body.method==='notifications/initialized'&&reply.statusCode===202;
    let errorCode=diagnosticResponseCode(response,reply.statusCode);
    // The SDK sends plain-text tool errors in SSE. Confirm schema rejection
    // against the registered input schema without retaining the SDK's message.
    if(!context.handlerEntered&&context.fieldPaths?.length&&(object(response.result).isError===true||response.error))errorCode='INPUT_VALIDATION_ERROR';
    const base:Omit<DiagnosticEnvelope,'eventId'|'stage'|'outcome'>={source:'server',tool,
      startedAt:context.startedAt.toISOString(),completedAt:completedAt.toISOString(),durationMs:Math.max(0,completedAt.getTime()-context.startedAt.getTime()),
      traceId:context.traceId,httpStatus:reply.statusCode,
      ...(context.schemaHash?{schemaHash:context.schemaHash}:{}),...(context.contractHash?{contractHash:context.contractHash}:{}),
      ...(context.fieldPaths?.length?{fieldPaths:context.fieldPaths}:{}),
      ...(typeof body.id==='string'||typeof body.id==='number'?{callIdHash:hash(String(body.id))}:{}),
      ...(typeof args.operationId==='string'&&/^[A-Za-z0-9_-]{12,128}$/.test(args.operationId)?{operationIdHash:hash(args.operationId)}:{}),
      ...(typeof args.actionId==='string'&&UUID.test(args.actionId)?{actionId:args.actionId}:{}),
      ...(Number.isInteger(args.taskIndex)&&Number(args.taskIndex)>=0&&Number(args.taskIndex)<12?{taskIndex:Number(args.taskIndex)}:{}),
      ...(typeof object(response.error).code==='number'?{rpcCode:object(response.error).code as number}:{})};
    const header=request.headers['x-w3bench-diagnostic-case'];
    const caseId=typeof header==='string'&&UUID.test(header)?header:undefined;
    let recorded=context.captureAvailable&&(!!wire?.complete&&recognized||noResponseExpected);
    const failureStage:DiagnosticEnvelope['stage']=context.failureStage??(object(response.error).code===-32700?'ingress':!context.principal&&(reply.statusCode===401||reply.statusCode===403)?'authentication':
      !context.handlerEntered&&(typeof object(response.error).code==='number'||errorCode==='UNSUPPORTED_MCP_CLIENT_PROFILE'||errorCode==='INPUT_VALIDATION_ERROR')?'sdk_validation':context.handlerEntered?'handler':'ingress');
    const stages:DiagnosticEnvelope['stage'][]=['ingress',...(context.principal||failureStage==='authentication'?['authentication' as const]:[]),
      ...(context.handlerEntered||failureStage==='sdk_validation'?['sdk_validation' as const]:[]),
      ...(context.handlerEntered?['handler' as const]:[]),'receipt'];
    const timing=(stage:DiagnosticEnvelope['stage'])=>{
      const [start,end]=stage==='ingress'?[context.startedAt,context.authStartedAt??completedAt]:
        stage==='authentication'?[context.authStartedAt??context.startedAt,context.authCompletedAt??completedAt]:
        stage==='sdk_validation'?[context.sdkStartedAt??context.authCompletedAt??context.startedAt,context.handlerStartedAt??completedAt]:
        stage==='handler'?[context.handlerStartedAt??context.startedAt,context.handlerCompletedAt??completedAt]:
        [context.receiptStartedAt??context.handlerCompletedAt??completedAt,completedAt];
      return{startedAt:start.toISOString(),completedAt:end.toISOString(),durationMs:Math.max(0,end.getTime()-start.getTime())};
    };
    // One 100ms HTTP observation budget, not 100ms for each stage. Background
    // persistence has its own 2-connection pool and bounded SQL lock waits.
    const saved=await captureDiagnosticWork(async()=>{
    let all=true;
    for(const stage of stages){
      const failed=!!errorCode&&stage===failureStage;
      const event:DiagnosticEnvelope={...base,...timing(stage),eventId:randomUUID(),stage,outcome:failed?'error':recognized||noResponseExpected||stage==='authentication'&&!!context.principal?'success':'unknown',...(failed?{errorCode}: {})};
        try{
          const evidence=failed&&context.principal&&caseId?await deriveDiagnosticPolicyEvidence(deps,
            {principal:context.principal,caseId,tool,errorCode:errorCode!,arguments:args}):undefined;
          if(!(await recordServerDiagnostic(deps,{...(context.principal?{principal:context.principal}:{}),...(caseId?{caseId}:{}),event,...(evidence?{evidence}:{})})).recorded)all=false;
        }
        catch{
          // A forged/foreign case header must not suppress bounded anonymous evidence.
          if(caseId)await recordServerDiagnostic(deps,{event});
          all=false;
        }
    }
    return all;
    },100);
    if(saved!=='recorded')recorded=false;
    const metadata={traceId:context.traceId,capture:recorded?'recorded':'unavailable',...(errorCode?{errorCode}:{}),
      ...(context.schemaHash?{schemaHash:context.schemaHash}:{}),...(context.contractHash?{contractHash:context.contractHash}:{}),
      ...(context.fieldPaths?.length?{fieldPaths:context.fieldPaths}:{})};
    let attached=false;
    const rewritten=wire?.rewrite(message=>{const result=attachDiagnosticMetadata(message,body.id,metadata);attached||=result.attached;return result.message;});
    if(recognized&&response.jsonrpc==='2.0'&&!attached)recorded=false;
    reply.header('X-W3Bench-Diagnostic-Trace',context.traceId);
    reply.header('X-W3Bench-Diagnostic-Capture',recorded?'recorded':'unavailable');
    if(attached&&rewritten!==undefined){reply.removeHeader('content-length');return rewritten;}
    return payload;
  });
  return {
    authenticationStarted(request:FastifyRequest){const context=contexts.get(request);if(context)context.authStartedAt=new Date();},
    sdkStarted(request:FastifyRequest){const context=contexts.get(request);if(context)context.sdkStartedAt=new Date();},
    handlerCompleted(request:FastifyRequest){const context=contexts.get(request);if(context)context.handlerCompletedAt=new Date();},
    receiptStarted(request:FastifyRequest){const context=contexts.get(request);if(context)context.receiptStartedAt=new Date();},
    async authenticated(request:FastifyRequest,principal:DiagnosticPrincipal){
      const context=contexts.get(request);if(context)context.principal=principal;
      const header=request.headers['x-w3bench-diagnostic-case'];
      if(header===undefined){if(context)context.authCompletedAt=new Date();return;}
      if(typeof header!=='string'||!UUID.test(header)){if(context)context.failureStage='authentication';throw new HttpError(400,'INVALID_ARGUMENTS','Diagnostic case reference is invalid');}
      const rows=await (options.authorizationDb??deps.db).execute(sql`SELECT id FROM oid_mcp_diagnostic_case WHERE id=${header}::uuid
        AND owner_id=${principal.ownerId}::uuid AND agent_id=${principal.agentId}::uuid AND connection_id=${principal.connectionId}::uuid`);
      if(!(rows as unknown[]).length){if(context)context.failureStage='authentication';throw new HttpError(404,'DIAGNOSTICS_CASE_NOT_FOUND','Diagnostic case is not available');}
      if(context)context.authCompletedAt=new Date();
    },
    handlerEntered(request:FastifyRequest){const context=contexts.get(request);if(context){context.handlerEntered=true;context.handlerStartedAt??=new Date();}},
    toolRegistered(request:FastifyRequest,name:string,configuration:unknown){
      const context=contexts.get(request),params=object(object(request.body).params),config=object(configuration);
      if(!context||params.name!==name)return;
      try{
        const schema=config.inputSchema;
        if(!(schema instanceof z.ZodType))return;
        const published=z.toJSONSchema(schema,{io:'input'}),canonical=canonicalDiagnosticJson(published);
        if(Buffer.byteLength(canonical)>65536)return;
        context.schemaHash=hash(canonical);
        context.contractHash=hash(canonicalDiagnosticJson({tool:name,inputSchema:published}));
        const result=schema.safeParse(params.arguments);
        if(!result.success)context.fieldPaths=[...new Set(result.error.issues.map(issue=>{
          const path=issue.path.join('.');return (DIAGNOSTIC_FIELD_PATHS as readonly string[]).includes(path)?path:'unknown_field';
        }))].slice(0,8) as DiagnosticEnvelope['fieldPaths'];
      }catch{/* A schema that cannot be safely fingerprinted remains explicitly unknown. */}
    },
    run<T>(request:FastifyRequest,work:()=>Promise<T>):Promise<T>{
      const context=contexts.get(request);if(!context)return work();
      return withDiagnosticRequest(async(boundary:DiagnosticBoundary)=>{
        if(boundary.outcome==='error')context.failureStage=boundary.stage;
        const header=request.headers['x-w3bench-diagnostic-case'],caseId=typeof header==='string'&&UUID.test(header)?header:undefined;
        const completed=new Date(),event:DiagnosticEnvelope={eventId:randomUUID(),traceId:context.traceId,source:'server',tool:'runs.task_action',
          stage:boundary.stage,outcome:boundary.outcome,startedAt:(context.handlerStartedAt??context.startedAt).toISOString(),completedAt:completed.toISOString(),durationMs:completed.getTime()-(context.handlerStartedAt??context.startedAt).getTime(),
          ...(boundary.actionId?{actionId:boundary.actionId}:{}),...(boundary.taskIndex===undefined?{}:{taskIndex:boundary.taskIndex}),...(boundary.errorCode?{errorCode:boundary.errorCode}:{})};
        const evidence=boundary.outcome==='error'&&boundary.errorCode&&context.principal&&caseId?
          await deriveDiagnosticPolicyEvidence(deps,{principal:context.principal,caseId,tool:'runs.task_action',errorCode:boundary.errorCode,arguments:object(object(object(request.body).params).arguments)}):undefined;
        const result=await recordServerDiagnostic(deps,{...(context.principal?{principal:context.principal}:{}),...(caseId?{caseId}:{}),event,...(evidence?{evidence}:{})});
        if(!result.recorded)context.captureAvailable=false;
      },work,()=>{context.captureAvailable=false;});
    }
  };
}
