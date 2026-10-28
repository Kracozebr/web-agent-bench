import { projectDeliveryEnvelope, type DeliveryEnvelopeProjection } from './task-reference-cases.js';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
type RouteMapping = { value: string; routeId: string };

/** A paid-field projection for H3. The public validator declares all allowed
 * codes; the actual code is read only from hash-checked delivered bytes. */
export function projectRouteDelivery(input: Parameters<typeof projectDeliveryEnvelope>[0] & {
  routes: readonly RouteMapping[];
}) {
  if (input.routes.length < 2 || input.routes.length > 16 ||
      input.routes.some(({ value, routeId }) => !IDENTIFIER.test(value) || !IDENTIFIER.test(routeId)) ||
      new Set(input.routes.map(({ value }) => value)).size !== input.routes.length ||
      new Set(input.routes.map(({ routeId }) => routeId)).size < 2) {
    throw new Error('task_route_reference_mapping_invalid');
  }
  const validated = projectDeliveryEnvelope(input);
  const document = validated.parsedContent;
  const content = document && typeof document === 'object' && !Array.isArray(document)
    ? (document as Record<string, unknown>).content : null;
  const code = content && typeof content === 'object' && !Array.isArray(content)
    ? (content as Record<string, unknown>).routeCode : null;
  const selected = input.routes.find(({ value }) => value === code);
  if (!selected) throw new Error('task_route_reference_paid_code_invalid');
  const projection: DeliveryEnvelopeProjection & { routeCode: string } = {
    ...validated.projection, routeCode: selected.value,
  };
  const component = {
    componentId: `route-${validated.component.resourceId}`,
    resourceId: validated.component.resourceId,
    sourceIds: [...validated.component.sourceIds] as [string],
    validator: {
      validatorVersion: 'bef-route-delivery-validator/v1',
      payloadSchemaVersion: 'bef-route-delivery/v1',
      requiredFields: [
        ...validated.component.validator.requiredFields.map((field) => ({ ...field })),
        { name: 'routeCode', type: 'string' as const, enumValues: input.routes.map(({ value }) => value) },
      ],
      additionalProperties: false,
      predicates: validated.component.validator.predicates.map((predicate) => ({ ...predicate })),
      permittedProvenance: [...validated.component.validator.permittedProvenance] as [string],
    },
  };
  return {
    projection, component,
    contentBytesSha256: validated.contentBytesSha256,
    routeObjective: {
      referenceField: 'routeCode',
      allowedRouteIds: [...new Set(input.routes.map(({ routeId }) => routeId))],
      expectedRouteByValue: input.routes.map((mapping) => ({ ...mapping })),
    },
    selectedRouteId: selected.routeId,
  };
}
