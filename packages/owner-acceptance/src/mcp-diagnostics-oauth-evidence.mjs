// AICODE-NOTE: SDK result enums and token-presence booleans are safe to retain;
// callback code/state, PKCE verifier and issued token values never enter evidence.
export function mcdOAuthEvidence(flow){
  const exchange=flow?.browserData?.exchange??{},callback=flow?.browserData?.callback??{};
  const results=new Set(['AUTHORIZED','REDIRECT','rejected','state_mismatch','no_code','not_attempted','denied']);
  const errors=new Set(['invalid_request','unauthorized_client','access_denied','unsupported_response_type','invalid_scope','server_error','temporarily_unavailable']);
  const status=value=>Number.isInteger(value)&&value>=100&&value<=599?value:null;
  return {boundary:'mcd_reference_sdk_oauth',exchangeResult:results.has(exchange.result)?exchange.result:'unknown',
    tokenEndpointStatus:status(exchange.tokenEndpointStatus),tokenPresent:exchange.tokenPresent===true,
    issuerMismatch:exchange.issuerMismatch===true,callbackStateMatches:callback.stateMatches===true,
    callbackIssuerMatches:callback.issuerMatches===true,callbackErrorCode:callback.errorCode==null?null:errors.has(callback.errorCode)?callback.errorCode:'unknown',
    tokenRequests:Array.isArray(exchange.tokenRequests)?exchange.tokenRequests.slice(0,4).map(r=>({
      status:status(r?.status),clientIdMatches:r?.clientIdMatches===true,redirectUriMatches:r?.redirectUriMatches===true,
      resourceMatches:r?.resourceMatches===true,pkceVerifierPresent:r?.pkceVerifierPresent===true,
      accessTokenPresent:r?.accessTokenPresent===true,refreshTokenPresent:r?.refreshTokenPresent===true,
    })):[],
  };
}
export function mcdOAuthAuthorized(flow){
  const value=mcdOAuthEvidence(flow);
  return value.exchangeResult==='AUTHORIZED'&&value.tokenEndpointStatus===200&&value.tokenPresent&&
    !value.issuerMismatch&&value.callbackStateMatches&&value.callbackIssuerMatches;
}
