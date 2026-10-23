## 1. Review and configuration

- [ ] 1.1 Review all 8 requirements and 12 mandatory scenarios, invitation/link-conflict/bootstrap/session defaults and exact production/test scope; obtain explicit approval before executable tests or product changes.
- [ ] 1.2 Pin Better Auth/provider/wallet versions, callback/domain/chain and origin configuration, session/nonce/invitation TTLs and throttles; verify the private provider fixture is feasible without a public auth bypass.
- [ ] 1.3 Reconcile the shared owner/user/account model and actual agent-access, billing and funding gates; define explicit configured administrator bootstrap without first-signup promotion.

## 2. Harness and persistence

- [ ] 2.1 Reuse shared active-delta harness work, merge approved OID observation contracts and add named HTTP/crypto/browser/actual-provider mappers/adapters; preserve baseline and other-capability inventories.
- [ ] 2.2 Add stable owner/admission, identity binding, invitation verifier/redemption, registration-policy revision and audit records using the selected identity store and database constraints.
- [ ] 2.3 Add real owner-session verification and pending/admitted principal projection for downstream services; reject forged owner/admin IDs and agent credentials on owner routes.

## 3. Sign-in and linking

- [ ] 3.1 Integrate Google callback/token correlation and verification through the actual provider adapter, with explicit failed/unknown exchanges and no session from unverified claims.
- [ ] 3.2 Implement actual SIWE message/signature/context verification and atomic nonce use for the approved wallet profile; reject replay, wrong purpose/context and unsupported wallets.
- [ ] 3.3 Implement explicit owner-bound Google/wallet linking with proof of the added method, stable owner identity and no automatic email-based merge.
- [ ] 3.4 Reject existing-identity and foreign-session conflicts without moving assets, roles or histories; do not introduce account merging or unlinking into this slice.
- [ ] 3.5 Implement session expiry, origin/CSRF enforcement and logout with the reviewed separation from explicit agent revocation and withdrawal proof.

## 4. Pilot admission

- [ ] 4.1 Implement private single-use invitation issuance/status/revocation with stored verifiers and secret-safe audit under configured administrator authority.
- [ ] 4.2 Commit verified owner activation and invitation redemption atomically, including concurrent claims, failed auth, lost responses and restart-safe retries.
- [ ] 4.3 Implement audited closed/open new-admission policy and returning-owner behavior without changing existing identities, agents, balances, financial rights or bonus terms.
- [ ] 4.4 Integrate actual agent-card, delegated-access and real-funding exposure gates with admission; verify bonus-only usage and independent withdrawal setup without automatic bonus issuance.

## 5. Web pages and evidence

- [ ] 5.1 Add actual sign-in, invitation activation, explicit-link and private account pages plus scoped administrator invitation/mode controls; verify direct API enforcement too.
- [ ] 5.2 Execute approved local HTTP/PostgreSQL/crypto/browser/provider-contract scenarios with actual verification, integrated product gates, concurrency and restart evidence; label the local provider boundary.
- [ ] 5.3 Execute the mandatory actual Google test-project/account and selected browser-wallet gate, including invitation activation, explicit linking and returning under the other method; missing resources block this gate.
- [ ] 5.4 Verify secret-free evidence and read-only identity/redemption replay with original paths/hashes; do not repeat sign-in, issuance, grants or product actions during replay.
- [ ] 5.5 Complete semantic audit, JUnit and source/Git/harness/contract provenance; sync and archive only when every approved mandatory gate passes, without claiming money movement or universal wallet support.
