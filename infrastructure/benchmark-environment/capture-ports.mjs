export function capturePorts(env) {
  const port=(name,fallback)=>{const value=env[name]??String(fallback);if(!/^[1-9][0-9]{0,4}$/.test(value)||Number(value)>65535)throw new Error(`${name} must be a valid TCP port`);return Number(value)};
  return {rpcA:port('BEF_LOCAL_RPC_A_HOST_PORT',18545),rpcB:port('BEF_LOCAL_RPC_B_HOST_PORT',28545)};
}
