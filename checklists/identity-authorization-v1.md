# Identity, authorization and trust-boundary review — v1

This is a **platform-agnostic investigation and test-design catalog**, derived from generalized patterns repeatedly observed in separately scoped source audits. It MUST NOT be interpreted as proof that any specific client is exploitable. Do not include client names, source secrets, internal URLs, real test accounts or incident evidence in this public checklist.

**Two evidence classes:** an independently cross-reviewed *source defect* can be `SOURCE_VERIFIED`; a claimed runtime exploit requires `LIVE_VERIFIED` with scoped synthetic tests. A code-path review cannot establish the active production environment, successful attack or compromised server.

## 1. Identity providers and token trust across services

| ID | Review objective | Negative/positive verification in approved UAT |
|---|---|---|
| ID-01 | Map each issuer, relying service, intended audience and algorithm/key; reject weak default/fallback signing secrets and unknown candidate keys | Test signed fixture from wrong issuer/audience and legitimate key; never use real leaked keys |
| ID-02 | Require appropriate token expiry, not-before, status, revocation and accepted algorithm constraints for the actual token profile | Expired/revoked/disabled user blocked; valid synthetic token still works |
| ID-03 | Resolve current user, role, organization, employment/relationship status and resource ownership from trusted server-side data | User removed, reassigned, demoted or moved tenant loses privilege without waiting for old UI refresh |
| ID-04 | Audit shared secrets and multi-key rotation: avoid default/fallback keys and unbounded accepting old secrets | Key-rotation tests with explicit decommission schedule and reject-old-secret evidence |
| ID-05 | No tokens in URL query strings, fragments forwarded to servers, Referer logs or cross-application handoff histories | One-time short-lived code exchange on staging, then verify no sensitive URL retention |
| ID-06 | Identify secrets in current tree, branch tips, history, container layers, CI variables and obsolete environment overlays; attest rotation | Private vault and rotation proof, not raw credential values |
| ID-07 | Verify server-side per-service identity decisions; frontend role gating is never authorization | Direct API role tests with synthetic actors and no client UI reliance |

## 2. Authorization completeness across every route and object

| ID | Review objective | Verification |
|---|---|---|
| AUTH-01 | Inventory every backend method and route (GET/POST/PUT/PATCH/DELETE, socket events, device callbacks, uploads, internal webhooks) | Method→route→middleware→service function→permission→tenant selector table |
| AUTH-02 | Deny-by-default; identify optional auth, skip lists, suffix/substring exemptions, onboarding exceptions and dynamic route matching | Negative tests on dedicated fixture routes with lookalike names/ambiguous path segments |
| AUTH-03 | Creation, bulk creation, password reset, role assignment and profile update require the right actor/target policy | Ordinary synthetic user cannot create privileged account or reset another user's password |
| AUTH-04 | Destructive operations require least privilege, tenant/object scope, confirmation/audit and recovery strategy | Low-privilege actor denied safe fixture reset/delete; admin action logged and recoverable |
| AUTH-05 | Organization/tenant filters applied in the data layer even if front-end sends identifiers | Cross-tenant GET/search/count/write denied using synthetic tenant pairs |
| AUTH-06 | All routes with the **same business side effect** have equivalent authority rules, including generic bulk/import/legacy/admin alternatives | Secure specialized route does not mask an insecure generic route |
| AUTH-07 | Object-level ownership includes nested entities, download URLs, exports, file storage and archive/status changes | Two same-role identities and two tenants cannot see or mutate each other's test objects |
| AUTH-08 | Permission reflects current assignment relationship (manager/rater/delegation) and revocation | Removed rater/manager cannot read old private workflow data |
| AUTH-09 | Aggregations, list filters, metrics, logs, full-text searches and pagination follow same actor+tenant constraints | Authorization matrix for count/list/export parity |
| AUTH-10 | Destructive operations log actor/resource/tenant and cannot be retried/replayed without controls | Synthetic audit/event record and idempotency test |
| AUTH-11 | Deny if user/service/org lookup fails or returns null; never retain unchecked claims from an unresolvable actor | Synthetic unregistered identity cannot gain role privileges |
| AUTH-12 | Authorization must be tested through APIs, not inferred from hidden UI controls | Direct approved test-account requests and independent responses |

## 3. Input and query security

| ID | Review objective |
|---|---|
| INPUT-01 | Reject client-supplied Mongo/NoSQL operators and raw filters; validate scalar and object schemas before query construction |
| INPUT-02 | Construct tenant/org criteria server-side and prevent user filters from overriding them through merging, aggregation or OR clauses |
| INPUT-03 | Check parameterization, command/API injection, template/HTML sinks and safe URL schemes with approved synthetic fixtures |
| INPUT-04 | Identify stored XSS→browser-token→API authorization chains; do not claim exploitation without an approved reproduction |
| INPUT-05 | Authenticate uploads and downloads; restrict SVG/active types as required, file sizes, content sniffing, access controls and safe storage keys |
| INPUT-06 | Verify consistent access policy on public uploads, exported documents, alternate fallback or signed links |
| INPUT-07 | Review external URL fetches, HTTP response integration, CORS exact-origin policy and origin-prefix lookalikes |
| INPUT-08 | Classify suspicious dormant encoded artifacts or unused external URLs as evidence needing provenance verification; do **not** decode/execute/fetch live suspicious payloads as a scanner default |

## 4. Safe regression method

For each control, the security agent should produce:

1. **Actual source evidence** (method, route, middleware, service call, expected role, tenant scope, file/line), distinguishing observed code from assumptions.
2. Use a positive test for a valid synthetic role and tenant. Use negative tests for anonymous, lower-role, other-tenant, revoked and alternate-route cases.
3. **Risk and exploit prerequisites** separately: source bug, relevant user capability, reachable deployed route, live proof (if authorized), and business impact.
4. **Remediation suggestion** based on centrally enforced policy with object/tenant check in service/data access layer. Use short-lived scoped tokens and key custody where relevant.
5. **Retest and closure gate**: source PR alone = `SOURCE_PATCHED`, only independent authorized deployed behavior test = `REMEDIATED_VERIFIED`. Legacy/alternate path coverage remains open until measured.

Use no real identities, production data, credential values, mass export, destructive reset, external lateral testing or stealth probes. Fail closed on missing accounts/permissions, and preserve all UNKNOWNs.

## References

- OWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- OWASP JSON Web Token Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html
- OWASP NoSQL Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html
- OWASP WSTG v4.2 authorization tests: https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/
- OWASP ASVS v5: https://asvs.owasp.org/
- OWASP API Security Top 10:2023: https://owasp.org/API-Security/editions/2023/en/0x00-header/

Witch Dog is an independent open-source project; no external standards organization endorses it.
