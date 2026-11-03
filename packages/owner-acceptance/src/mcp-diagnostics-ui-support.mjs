import assert from 'node:assert/strict';

/** Actual owner policy action. Leave an already-enabled checkbox unchanged. */
export async function ensureMcdTrainingAllowed(page,agentId){
  const card=page.getByTestId('agent-card-'+agentId),training=card.getByTestId('agent-permission-training');
  await training.waitFor({state:'visible'});
  if(await training.isChecked())return;
  await training.check();
  const saved=page.waitForResponse(response=>new URL(response.url()).pathname===`/api/owner/agents/${agentId}/permissions`&&response.request().method()==='PUT');
  await card.getByTestId('agent-permissions-save').click();assert.equal((await saved).status(),200);
}
