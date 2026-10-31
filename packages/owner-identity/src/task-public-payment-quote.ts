/** Public quotes are six legacy terms or those terms plus the complete domain group.
 * This validator never normalizes the retained object or expands economic acceptedTerms. */
type RecordValue = Record<string, unknown>;
const rec = (value: unknown): value is RecordValue => !!value && typeof value === 'object' && !Array.isArray(value);
const text = (value: unknown, max: number): value is string => typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
export type PublicPaymentIdentity = {name?: string; version?: string; paymentFlow?: string};
export function publicPaymentIdentity(policy: unknown): PublicPaymentIdentity {
  if (!rec(policy)) return {};
  const domain = rec(policy.eip712Domain) ? policy.eip712Domain : {};
  return { ...(typeof domain.name === 'string' ? {name:domain.name} : {}),
    ...(typeof domain.version === 'string' ? {version:domain.version} : {}), paymentFlow:'authorization' };
}
export function publicPaymentQuoteMatches(value: unknown, policy: PublicPaymentIdentity = {}): value is RecordValue {
  if (!rec(value)) return false;
  const keys=Object.keys(value).sort().join(',');
  const legacy=keys==='amount,asset,network,payTo,scheme,transferMethod';
  if (!legacy && keys!=='amount,asset,name,network,payTo,paymentFlow,scheme,transferMethod,version') return false;
  if (!text(value.scheme,80) || !text(value.network,128) || !text(value.transferMethod,80) ||
      typeof value.asset!=='string' || !/^0x[0-9a-f]{40}$/i.test(value.asset) ||
      typeof value.payTo!=='string' || !/^0x[0-9a-f]{40}$/i.test(value.payTo) ||
      typeof value.amount!=='string' || !/^(?:0|[1-9][0-9]{0,77})$/.test(value.amount)) return false;
  return legacy || (text(value.name,128) && text(value.version,128) && value.paymentFlow==='authorization' &&
    Object.entries(policy).every(([key,expected])=>expected===undefined || value[key]===expected));
}
export function publicInspectionQuotesMatch(body: unknown, kind: 'inspect_offer'|'inspect_catalog', policy: PublicPaymentIdentity = {}): boolean {
  if (!rec(body)) return false;
  const resources=kind==='inspect_offer'?[body]:Array.isArray(body.catalog)?body.catalog:[];
  if (!resources.length) return false;
  let disclosed: boolean|undefined;
  return resources.every(resource=>{
    if (!rec(resource) || !Array.isArray(resource.offers) || !resource.offers.length) return false;
    const quotes=resource.offers.map(offer=>rec(offer)?offer.payment:null);
    if (!quotes.every(quote=>publicPaymentQuoteMatches(quote,policy))) return false;
    for (const quote of quotes) {
      const modern=rec(quote) && Object.hasOwn(quote,'version');
      if (disclosed===undefined) disclosed=modern;
      else if(disclosed!==modern) return false;
    }
    if (resource.payment!==undefined) {
      if (!publicPaymentQuoteMatches(resource.payment,policy)) return false;
      const root=resource.payment;
      if (!quotes.every(quote=>rec(quote) && ['name','version','paymentFlow'].every(key=>quote[key]===root[key]))) return false;
    }
    return true;
  });
}
