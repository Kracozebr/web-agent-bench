import assert from 'node:assert/strict';
import test from 'node:test';
import { h3CatalogReadHeaders } from '../src/probe/task-h3-capture.js';

test('H3 public catalog read carries scoped auth and a fresh idempotency key', () => {
  const session = { runToken: 'r'.repeat(48), generationId: '4e7dfbd8-7a95-4a9a-8613-a5a212c2f651' };
  const first = h3CatalogReadHeaders(session);
  const second = h3CatalogReadHeaders(session);
  assert.equal(first.authorization, `Bearer ${session.runToken}`);
  assert.equal(first['X-BEF-Generation'], session.generationId);
  assert.match(first['Idempotency-Key']!, /^[0-9a-f-]{36}$/i);
  assert.notEqual(first['Idempotency-Key'], second['Idempotency-Key']);
});

