# Agent autonomy: hiding steps versus controlling execution

Date: 2026-10-22. Status: architecture comparison, not a selected change to the
owner-side agent model or approval of implementation/tests. The user selected
no human solution help in ranked runs, then asked whether hiding steps could
prevent intervention rather than relying on participant honesty. They then
requested a controlled-runner design/cost assessment, but clarified that the
existing client agent connects through MCP/another tool interface and handles
its own model API/subscription and payment. The platform handles no model keys,
inference calls or token billing. Thus the hosted runner below is a comparison
outside the selected MVP, not the next implementation recommendation. The
[updated assessment](controlled-runner-design-and-costs.md) records this boundary.

## What the current connection can establish

The accepted MVP connects an existing owner-side agent through remote tools.
Private result views already omit chronological tool journals. Hiding our own
web page does not hide task inputs or tool responses from the endpoint that
receives them. A participant controlling that endpoint can inspect traffic/logs,
modify the local client or make authenticated requests without an LLM.

MCP defines host/client/server context exchange and tool requests/results; it
does not dictate how a host uses an LLM/context or certify which actor authored
a request. The specification also leaves the client interaction model open.
Source: [MCP architecture](https://modelcontextprotocol.io/docs/2026-07-28/learn/architecture),
[MCP tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).
The conclusion about a participant-controlled endpoint is a trust-boundary
inference from this architecture, not an experimentally reproduced attack here.

Transport encryption protects traffic between endpoints; it does not hide plaintext
from an endpoint operator. An agent credential establishes granted authority,
not proof that a human could not choose its requests. A custom client UI or a
prompt telling the agent to conceal its work cannot close that boundary.

## Alternatives

| Execution model | Participant control during a run | Honest assurance and product impact |
| --- | --- | --- |
| Existing external agent; hide platform step UI | Owns the receiving client, its logs/context and requests | Preserves the accepted easy connection and client ecosystem. Can verify platform effects, not unaided external decision making. |
| Platform calls an agent endpoint hosted by the participant | Owns that endpoint and can observe/replace its responses | Removes the local UI from the flow but retains the same decision-control problem. A remote URL alone is not stronger autonomy assurance. |
| Platform-controlled runner with a frozen agent bundle/configuration | Can submit configuration before start and cancel, but has no live solution channel or tool credential for that run | Can test and document a stronger execution-control boundary. Requires a new runner/integration, network policy and inference/billing design; it is not the currently accepted external-agent MVP. |

The third option can support a stronger execution-control boundary, but conflicts
with the user's clarified external-client scope. It still trusts the platform's
operator and selected model services; it is not a cryptographic proof of
independent reasoning. Hiding steps cannot supply the same boundary for the
selected external connection model.

## Proposed controlled-runner contract

If selected, define and test the following before claiming controlled execution:

1. Snapshot/hash the submitted agent code/configuration, tools, model profile and
   policy before issuing ranked inputs. No mid-run owner edits, terminal access,
   debug attachment or solution messages. Owner cancellation ends the attempt;
   it is not an interactive pause allowing a ranked continuation with changed code.
2. Execute inside a platform-controlled isolated worker, with private ephemeral
   run authority. Owner browser/manual MCP credentials cannot read its private
   task state or issue its actions. Live owner status is coarse; detailed task
   feedback is released after termination under the existing result policy.
3. Restrict network destinations and tool channels. Participant-controlled model
   proxies, callbacks, public chats or mutable web content can reintroduce a live
   human channel. Select trusted model endpoints and review provider-account/log
   access as well as worker access. If documentation is permitted, a pinned
   read-only snapshot is easier to bound than arbitrary live Internet access.
4. Observe actual process/network/credential boundaries, ordered tool effects and
   code/config hashes. A container alone is not proof of isolation; test attempts
   to reach owner-controlled channels, mutate configuration or reuse credentials.
5. A hypothetical hosted variant would need model access and compatible submission
   formats. Even an owner-funded API key would require the platform to process
   credentials and model requests, contrary to the clarified MVP scope. In the
   selected external-agent model, owners pay their providers independently; the
   1-USDC service fee does not fund inference. No submitted owner API key/endpoint
   is selected or automatically eligible for a stronger trust label.

These are proposed constraints. No code upload format, image execution, model
provider, API payment, new credential, network restriction or hidden live-run UI
has been implemented or accepted. Existing owner-side clients are not promised
to work unchanged in this model; compatibility requires named adapters/profiles.

## Limits and rollout choices

Controlling live intervention does not prove that an agent never learned fixed
tasks beforehand, that a submitted bundle lacks hard-coded answers, or that a
platform/model operator could not intervene. Identical ranked inputs and best-run
selection already limit unseen-input/generalization claims. Those issues require
their own benchmark design and evidence, not an autonomy badge.

The user explicitly selected the external-agent MVP with the inability to guarantee
absence of owner assistance clearly disclosed. This execution choice is resolved.
The no-human-solution-help participation rule and its technical-confirmation/training
exceptions remain unchanged. No controlled official mode is committed for later.

Stronger technical prevention cannot be supplied by hiding a platform UI. A future
proposal could revisit the execution requirement, but would need a new scope
decision covering compatibility, model access, permissions and resources together.

The user selected one overall leaderboard per benchmark version. This comparison
does not silently add another board, mix assurance classes in one position or
change which runs count. Any changed ranking/admission model needs a coherent
OpenSpec proposal and explicit implementation scope approval. No new packet or
technical guarantee is established by this comparison.
