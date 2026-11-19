# Security audit lessons and ZAP runner reliability — 2026-11-20

**Source basis:** Two operator-provided assessment summaries. One was a static, read-only audit of multiple connected application repositories. The second was a passive-only OWASP ZAP pilot whose agent used a manual direct execution after a Witch Dog plan-validation HOLD. This public document intentionally excludes all client identifiers, domains, source paths, credentials, incident IOC details and private output.

## Lessons from the source audit

The static audit's independently reviewed high-risk source findings included:

- JWT signing key fallback, shared or weak signing secrets, multiple accepted candidate keys and missing relevant token constraints.
- Backend account creation and password-change operations without target-specific role/authority enforcement.
- Destructive administrative operations authorized by an overly broad platform role, without proportional audit/recovery controls.
- Cross-tenant access from user-supplied NoSQL query filters, unscoped cross-organization search and mutations.
- Authorization enforced on specialist routes but bypassed by a generic alternate endpoint with the same underlying business effect.
- Stored XSS combined with browser-accessible tokens, unauthenticated file-serving, permissive upload types and incomplete access controls.
- Long-lived tokens forwarded through URL query strings across applications.
- Suspicious dormant configuration references, leaked secrets in tracked files/containers, unverified dependency provenance and missing Git history/runtime access.

These are *source-verified* findings in the supplied audit, **not live exploit demonstrations in this project**. The source audit did not run code, test live APIs, inspect real cloud secrets, or verify historical Git objects (Git unavailable). It also documented correctly guarded specialist authorization routes; distinguish positive evidence from insecure alternate routes.

**Reusable controls:** see `checklists/identity-authorization-v1.md`. Review every HTTP method, route, actor, object, tenant, business state machine and alternate entry point. Carry a trust graph for issuers, audiences, keys and relying services. Store risk evidence privately.

## Lessons from the passive ZAP pilot

The operator reported six ZAP candidates after one approved root GET. The substantive ones matched missing header observations also seen with the existing baseline. This corroborates a *specific header/edge configuration*, not independent proof of SQL injection, XSS, authz failure or full VAPT coverage. None of the high-impact categories was tested in that run.

ZAP's `-autocheck` reportedly returned code 2 for an unrecognized Environment `maxDuration` parameter in the generated plan; an agent then ran direct `-autorun` outside Witch Dog's gate. That is a gate bypass, **not an attested Witch Dog run**, despite the agent's transparency about it. ZAP version/add-on compatibility should be resolved in the plan generator.

ZAP documents exit codes: `0` success, `1` errors, `2` warnings. `-autorun` can finish with code 2 even with `failOnWarning: false`. In contrast, **nonzero `-autocheck` must HOLD** until its diagnostics are resolved; never run a direct shell workaround to change execution provenance.

## Engine policies and regression contracts

1. Remove the compatibility-sensitive Environment-level `maxDuration` from generated plans; keep subprocess timeouts. Re-check the installed ZAP/add-on version through the actual `-autocheck` command.
2. Disable implicit spider form submission and auxiliary discovery by default. Explicit synthetic staging scopes and network enforcement remain mandatory.
3. `-autocheck` nonzero: no network testing, report HELD and no verified receipt.
4. `-autorun` code 2 with a complete bounded raw report: mark `COMPLETE_WITH_WARNINGS`, not clean PASS; preserve warnings for operator analysis.
5. Generate a runner receipt binding engagement, scope digest, plan digest, precheck exit, autorun exit and raw report hash. This is **integrity parity**, not a cryptographic attestation of the runner identity.
6. Permit importing raw reports from external runs for private forensic triage, but report `EXTERNAL_UNVERIFIED` until separately validated. Do not silently upgrade by manually changing manifest status.
7. Carry historical high-impact source findings as OPEN/RETEST_UNKNOWN until independently retested with authorized synthetic fixtures or verified running artifacts.
8. Do not count multiple scanners probing one root URL as full route coverage; report unique routes/methods/roles and all untested trust boundaries.
9. A missing security header is a configuration observation, not proof of exploitability. Do not treat active-scan candidates as independently confirmed vulnerabilities.

## Acceptance test to complete before production-grade claims

Qualify the exact installed ZAP binary and Automation Framework add-ons against a disposable synthetic application. Exercise preflight, plan, autocheck, autorun, ingest and reporting for clean, warning and invalid-plan conditions. Test one deliberately vulnerable synthetic injection fixture and a negative-control fixture, plus role/object authorization cases. No client data, privileged service identity, production secrets or unrestricted network route should be used.

## Primary references

- https://www.zaproxy.org/docs/automate/automation-framework/
- https://www.zaproxy.org/docs/desktop/addons/automation-framework/environment/
- https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-spider/
- https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html

No live client environments were changed by producing this public guidance.
