import type {FastifyInstance,FastifyRequest} from 'fastify';
import type {OwnerDatabase} from './db.js';
import {HttpError} from './http-error.js';
import {getParticipantTrainingDiagnostics,listParticipantBillingHistory,listParticipantGrants,parseCabinetPageQuery} from './participant-cabinet-service.js';

export interface ParticipantCabinetDependencies {
  db:OwnerDatabase;cabinetCursorSecret:string;
  resolveOwner(request:FastifyRequest):Promise<{owner:{id:string;admissionStatus?:string}}>;
  rateLimit(request:FastifyRequest,group:string,limit:number):Promise<void>;rateLimitMax:number;
}
export function registerParticipantCabinetRoutes(app:FastifyInstance,deps:ParticipantCabinetDependencies){
  const read=async(request:FastifyRequest)=>{
    await deps.rateLimit(request,'participant-cabinet',deps.rateLimitMax);
    const context=await deps.resolveOwner(request);
    if(context.owner.admissionStatus!==undefined&&context.owner.admissionStatus!=='admitted')throw new HttpError(403,'OWNER_NOT_ADMITTED','Owner admission is required');
    return context.owner.id;
  };
  for(const resource of ['grants','history'] as const)app.get(`/api/owner/billing/${resource}`,async(request,reply)=>{
    reply.header('Cache-Control','private, no-store');
    try{
      const owner=await read(request),query=parseCabinetPageQuery(request.query as Record<string,unknown>);
      return await (resource==='grants'?listParticipantGrants:listParticipantBillingHistory)(deps.db,owner,query,deps.cabinetCursorSecret);
    }catch(error){if(error instanceof HttpError)return reply.code(error.status).send({error:{code:error.code,message:error.message}});
      return reply.code(500).send({error:{code:'INTERNAL_ERROR',message:'The request could not be completed'}})}
  });
  app.get<{Params:{runId:string;taskId:string}}>('/api/owner/runs/:runId/tasks/:taskId/diagnostics',async(request,reply)=>{
    reply.header('Cache-Control','private, no-store');
    try{
      const owner=await read(request);
      if(Object.keys(request.query as object).length)throw new HttpError(400,'INVALID_REQUEST','Unsupported query fields');
      return {diagnostics:await getParticipantTrainingDiagnostics(deps.db,owner,request.params.runId,request.params.taskId)};
    }catch(error){if(error instanceof HttpError)return reply.code(error.status).send({error:{code:error.code,message:error.message}});
      return reply.code(500).send({error:{code:'INTERNAL_ERROR',message:'The request could not be completed'}})}
  });
}
