import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { buildRunHandoffPrompt } from './run-handoff.js';
const intent = { id: '11111111-1111-4111-8111-111111111111', agentId: '22222222-2222-4222-8222-222222222222',
  mode: 'training' as const, taskIds: ['S1','M1','H1'], quote: { price:'0.500000', token:'USDC' as const, precision:6 as const }, cashCeiling:'0' };

test('handoff binds the reviewed card and selection without credential or incidental metadata leakage', () => {
  const prompt=buildRunHandoffPrompt({...intent, credential:'synthetic-do-not-copy', answer:'synthetic-hidden-answer'} as typeof intent);
  const selection=JSON.parse(prompt.split('\n').find(line=>line.startsWith('{'))!);
  assert.deepEqual(selection,{agentId:intent.agentId,intentId:intent.id,mode:'training',taskIds:intent.taskIds,
    quote:{price:'0.500000',token:'USDC'},cashCeiling:'0'});
  assert(!prompt.includes('synthetic-do-not-copy')); assert(!prompt.includes('synthetic-hidden-answer'));
  assert(prompt.includes(`identity.preflight with exactly agentId ${intent.agentId}`));
  assert(prompt.includes(`runs.accept_launch_intent with exactly intentId ${intent.id}`));
  const ranked=buildRunHandoffPrompt({...intent,mode:'ranked',taskIds:['S1','S2'],quote:{...intent.quote,price:'1.000000'},cashCeiling:'0.100000'});
  const rankedSelection=JSON.parse(ranked.split('\n').find(line=>line.startsWith('{'))!);
  assert.equal(rankedSelection.mode,'ranked');assert.equal(rankedSelection.quote.price,'1.000000');assert.equal(rankedSelection.cashCeiling,'0.100000');
});

test('handoff completes one admitted run through waiting and prevents duplicate effects or invented terminal grades', () => {
  const prompt=buildRunHandoffPrompt(intent);
  for(const clause of ['Do not stop after accepting the intent','immediately call runs.current_task',
    'A null task is not proof that the run ended','run.terminal === true', 'follow retryAfterMs',
    'runs.task_action_status for the original actionId','Do not resubmit an ambiguous payment',
    'separate pay and retrieve actions, not purchase','report it as unresolved',
    'Do not change these limits or create another intent or run','Never infer scores from payment confirmation'])
    assert(prompt.includes(clause),`Missing execution boundary: ${clause}`);
});

test('clipboard and visible manual fallback use the same complete handoff builder', async () => {
  const ui=await readFile(new URL('../components/run-launch-panel.tsx',import.meta.url),'utf8');
  assert(ui.includes('const prompt = buildRunHandoffPrompt(intent);'));
  assert(ui.includes('await copyText(prompt)'));
  assert(ui.includes('>{buildRunHandoffPrompt(intent)}</p>'));
  assert(!ui.includes('const prompt = `Run the free Web3 Agent Bench preflight'));
});
