# Witch Dog — Web Application VAPT Checklist v1

**Purpose:** A professional, reproducible web-application assessment catalog for authorized clients. **Not** a claim that Witch Dog automatically performs a full penetration test or has any particular certification.

### Basis and intellectual property

This is an original Witch Dog test catalog **informed by**, not copied from, these independently maintained resources:

- [OWASP WSTG v4.2](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/): versioned testing methodology across information gathering, configuration, identity, authentication, authorization, session, input, errors, cryptography, business logic and client side.
- [OWASP ASVS 5.0.0](https://asvs.owasp.org/): testable *verification requirements*. ASVS L1 is a minimum starting target; L2 is the practical target for most business applications; L3 applies to selected high-assurance systems. A black-box homepage scan cannot establish ASVS L1 compliance.
- [OWASP Top 10:2025](https://top10.owasp.org/2025/): web application risk awareness and priorities (not a complete test plan).
- [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x00-header/): object/field/function authorization, consumption, SSRF, inventory and unsafe upstream API use.
- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final): planning, assessment, analysis and remediation methodology.
- [OWASP ZAP scanning safety](https://www.zaproxy.org/faq/is-there-any-danger-when-scanning-with-zap-against-a-live-website-e-g-create-delete-update-corrupt-data/): spiders and active testing can have unintended effects.

These references and names remain their respective owners' intellectual property; the Witch Dog checklist uses independent descriptions and versioned source links. No OWASP or other organization endorses or certifies this project.

## Severity, testing tiers and evidence

The **scan is never more authoritative than its evidence**. Reference control IDs are Witch Dog's own identifiers, not mappings to individual numbered ASVS/WSTG tests.

| Tier | Scope | Authorization |
|---|---|---|
| **B** | Baseline: pre-agreed, low-impact remote observation; limited safe homepage request | User explicitly owns/has permission for exact URL; no extensions |
| **S** | Source/deployment evidence: authorized repository or live inventory review | Separate private repository/host approval |
| **U** | Controlled UAT: authenticated tests, synthetic personas, deliberate negative cases | Written rules of engagement (RoE) and staging/test account consent |
| **I** | Invasive: active fuzzing, payload injection, high volume probing, exploitation, DoS stress | Separate signed approval, isolated staging, rollback, rate/impact limits |

Witch Dog's initial `tools/web_baseline.py` executes **only the small B-tier subset described in its implementation**. Other B controls may require additional tools and are `UNKNOWN` until evidence exists. The agent does not execute U/I controls just because they appear below.

For every control, track `test_status=EXECUTED/DEFERRED/BLOCKED/NOT_APPLICABLE`, `verdict=PASS/FAIL/WARN/UNKNOWN/N/A`, the observation class `REMOTE_OBSERVED/SOURCE_DECLARED/HOST_OBSERVED/LIVE_VERIFIED/UNKNOWN/CONFLICTING`, method, redacted evidence, UTC date, source version, confidence, risk, limitations and a retest requirement.

### Baseline result interpretation and risk carry-forward

The BASELINE runs a single authorized GET of `/`, usually covering around ten header/TLS controls, not a meaningful sample of the full VAPT catalog. Good scores or zero High findings reflect **limited tests**, not secure authentication or authorization. Reports MUST label `NOT_A_VAPT`, retain high-impact `UNKNOWN` controls and preserve unresolved independent audit findings in the **private** client register. A 200 landing page is availability evidence, not a secure application conclusion. Compare source vs CDN/SPA/API and running release before reconciling contradictory header evidence. Do not claim TLS minimum supported version from a single TLSv1.3 negotiation.

Header presence alone is insufficient for narrow PASS: inspect effective script restriction under CSP, valid `frame-ancestors` or X-Frame-Options, exact `nosniff`, actual Referrer-Policy directive and sensitive Permissions-Policy grants. The absence of Referrer-Policy is not necessarily an active leak because of modern browser defaults; missing Permissions-Policy is a context-dependent hardening observation. See [pilot lessons](../docs/web-baseline-pilot-lessons.md).

## WEB-00 — Engagement scope and safe execution

*Crosswalk: NIST SP 800-115 planning and OWASP WSTG testing framework.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-00.01 | Confirm legal owner/explicit tester authorization for each exact origin | B | Written permission and scope |
| WEB-00.02 | Identify production, staging, dev and third-party dependencies; exclude vendor domains | B | Authorized origins and exclusions |
| WEB-00.03 | Define safe request limit, time window, no-go paths and emergency contact | B | Engagement record |
| WEB-00.04 | Define test identities, roles, tenant boundaries and synthetic dataset | U | Approved test-account matrix |
| WEB-00.05 | Define active testing impact, backup, restore and change approval | I | Signed RoE/rollback |
| WEB-00.06 | Verify scan identity and disable accidental proxy/credential reuse | B | Tool and network scope |
| WEB-00.07 | Define evidence-retention, model-provider and private report destination | B | Data handling approval |
| WEB-00.08 | Record scanner, checklist, model and source versions before the run | B | UTC tool manifest |

## WEB-01 — Application surface and information gathering

*Crosswalk: WSTG 4.1, ASVS architecture documentation, OWASP Top 10 A02:2025.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-01.01 | Identify authorized origin, DNS resolution and destination class | B | Pinned DNS outcome |
| WEB-01.02 | Inventory approved HTTP origins, subdomains and environment ownership | S | Owner-provided topology |
| WEB-01.03 | Record limited status/redirect behavior without crossing origins | B | One permitted response |
| WEB-01.04 | Recognize CDN, reverse proxy or WAF without attributing it to actual origin | B | Header observation with limits |
| WEB-01.05 | Enumerate routes/entry points from approved OpenAPI specification or route manifest | S | Versioned route inventory |
| WEB-01.06 | Identify distinct customer, admin, partner and machine-to-machine trust zones | S | Architecture and access matrix |
| WEB-01.07 | Review accidental public debug, admin or staging exposure | S | Authorized listener/deployment proof |
| WEB-01.08 | Find potentially sensitive backups, debug artifacts or exports in approved static inventory | S | Filenames and private access evidence |
| WEB-01.09 | Document third-party domains and exclude them from probes unless separately authorized | S | Owner-verified endpoint map |

## WEB-02 — Transport, TLS, HTTP, CDN and headers

*Crosswalk: WSTG 4.2/4.9, ASVS web front-end/communication requirements, OWASP Top 10 A02/A04:2025.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-02.01 | Validate HTTPS certificate chain and hostname at target endpoint | B | Verified TLS handshake |
| WEB-02.02 | Record certificate validity and policy without disabling verification | B | Certificate metadata (if available) |
| WEB-02.03 | Check presence and scope of HSTS on HTTPS | B | Strict-Transport-Security |
| WEB-02.04 | Inspect CSP structure and major unsafe directives; no inference from absence alone | B | Sanitized CSP |
| WEB-02.05 | Check X-Content-Type-Options and content-type consistency | B | Response headers |
| WEB-02.06 | Check frame embedding policy (CSP frame-ancestors or X-Frame-Options) | B | Header observation |
| WEB-02.07 | Review Referrer-Policy for excessive disclosure | B | Header observation |
| WEB-02.08 | Review Permissions-Policy on sensitive browser features | B | Header observation |
| WEB-02.09 | Inspect redirects and cross-origin destinations without following them | B | Status and sanitized location |
| WEB-02.10 | Check production HTTP->HTTPS enforcement and mixed-content issues | U | Controlled browser/session proof |
| WEB-02.11 | Verify supported TLS versions and cipher policy with approved dedicated tooling | U | TLS tool version and result |
| WEB-02.12 | Verify HTTP/2, HTTP/3 and feature-specific proxy prerequisites | S | Actual listener and config |
| WEB-02.13 | Check CDN/WAF edge versus bypassable origin separately | S | Authorized network topology |
| WEB-02.14 | Check effective DNS, ingress, reverse-proxy and service-routing parity | S | Running route and deployment graph |

## WEB-03 — Identity, authentication and account recovery

*Crosswalk: WSTG 4.3/4.4, ASVS identity/authentication, OWASP Top 10 A07:2025.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-03.01 | Map login/registration and identity providers without creating accounts | S | Approved flow diagrams |
| WEB-03.02 | Verify server-side authentication gates on protected routes | U | Synthetic anonymous/valid requests |
| WEB-03.03 | Confirm login error responses don't reveal unnecessary account existence | U | Test account controls |
| WEB-03.04 | Verify login, password reset and recovery have anti-automation protections | U | Bounded configured tests |
| WEB-03.05 | Assess password/credential policy and secure issuance; no real guessing | S | Auth policy and tests |
| WEB-03.06 | Check MFA enrollment, reset, step-up and bypass resistance | U | Test accounts and staged recovery |
| WEB-03.07 | Test lockout and throttling without real user disruption | U | Dedicated fixture and traffic ceiling |
| WEB-03.08 | Verify SSO/OIDC/SAML redirect URI, issuer, audience and signature validation | U | Approved test IdP and protocol evidence |
| WEB-03.09 | Check account activation, invitation and magic-link expiry and one-time semantics | U | Synthetic tokens and timestamps |
| WEB-03.10 | Verify sensitive account changes require reauthentication or equivalent safeguards | U | Synthetic persona and transaction |
| WEB-03.11 | Verify disabled, deleted and non-existent users cannot remain authenticated | U | Controlled state transitions |
| WEB-03.12 | Confirm no production default or shared operator credential is active | S | Rotation/revocation proof, never secret values |

## WEB-04 — Authorization and tenant isolation

*Crosswalk: WSTG 4.5, ASVS access control, OWASP Top 10 A01:2025, API1/API3/API5:2023.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-04.01 | Document users, service roles, tenants, organizations and permission boundaries | S | Role/actor matrix |
| WEB-04.02 | Test object-level authorization (BOLA/IDOR) using only synthetic objects | U | Allowed/denied response pair |
| WEB-04.03 | Test function/endpoint-level access for employee, admin and partner personas | U | Role-route matrix |
| WEB-04.04 | Test property-level restrictions on reads, writes and serialization | U | Synthetic field matrix |
| WEB-04.05 | Verify cross-tenant protections including indirect identifiers and nested resources | U | Two test tenants |
| WEB-04.06 | Confirm aggregate dashboards, counts and exports honor same actor scope | U | Counterexample tests |
| WEB-04.07 | Check temporary/signed links expire and are bound to permitted objects | U | Test-only signed resources |
| WEB-04.08 | Ensure backend authorization, not UI-only button gating | U | Authorized API negative test |
| WEB-04.09 | Check optional-auth onboarding/provisioning doesn't permit later anonymous mutations | U | Provisioned/unprovisioned fixture |
| WEB-04.10 | Verify JWT role/status/tenant claims against current actor records | U | Synthetic invalid/removed identity |
| WEB-04.11 | Verify separation of administrator and machine-to-machine authorization | S | Service scopes and routes |
| WEB-04.12 | Verify audit/read-history endpoints respect tenant access and pagination | U | Role/tenant matrix |

## WEB-05 — Sessions, cookies, CSRF and tokens

*Crosswalk: WSTG 4.6, ASVS session management and token handling.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-05.01 | Identify names and flags of cookies without collecting cookie **values** | B | Flag-only observation |
| WEB-05.02 | Verify sensitive session cookies use Secure and HttpOnly as applicable | B/U | Header flags and intent |
| WEB-05.03 | Verify SameSite policy and cross-site behavior on sensitive flows | U | Approved browser/control test |
| WEB-05.04 | Verify logout invalidates server-side sessions or tokens appropriately | U | Synthetic session transitions |
| WEB-05.05 | Verify privilege changes and password resets invalidate prior sessions | U | Before/after test identities |
| WEB-05.06 | Check idle and absolute session expiration | U | Policy and timed test |
| WEB-05.07 | Confirm no session tokens/passwords are retained in browser storage inappropriately | S | Approved client/source review |
| WEB-05.08 | Verify anti-CSRF protections on state-changing cookie-authenticated requests | U | Synthetic form/API requests |
| WEB-05.09 | Test JWT audience, issuer, expiry, signature algorithm and token revocation | U | Controlled invalid tokens |
| WEB-05.10 | Verify refresh-token rotation/reuse detection where relevant | U | Dedicated test identity |
| WEB-05.11 | Verify session IDs cannot be fixed across login or privilege escalation | U | Session pair comparison |
| WEB-05.12 | Verify cache headers on authenticated, sensitive responses | U | Authorized sample endpoint |

## WEB-06 — Input handling, injection, parsing and errors

*Crosswalk: WSTG 4.7/4.8, ASVS encoding/validation, OWASP Top 10 A05/A10:2025.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-06.01 | Map untrusted input entrypoints without sending attack strings | S | Route/source inventory |
| WEB-06.02 | Check server-side validation of type, bounds, format, size and relationships | U | Approved boundary cases |
| WEB-06.03 | Inspect output encoding and sanitization across HTML, JS, URL and Markdown contexts | S | Context-specific sink review |
| WEB-06.04 | Evaluate stored/reflected/DOM XSS in isolated UAT fixtures | I | Test payloads and safe render proof |
| WEB-06.05 | Evaluate SQL/NoSQL/ORM injection defenses without live data access | S/I | Parameterization/source or isolated proof |
| WEB-06.06 | Evaluate OS command injection and shell parameter separation in source | S/I | Approved code path |
| WEB-06.07 | Evaluate SSRF egress/URL parsing/redirect and DNS rebinding controls | S/I | Guard/egress proof in staging |
| WEB-06.08 | Evaluate path traversal, file inclusion and archive extraction isolation | S/I | Safe fixture paths |
| WEB-06.09 | Verify XML/XXE, unsafe parsers and JSON duplicate-key behavior | S/I | Parser config and isolated tests |
| WEB-06.10 | Check insecure deserialization and unsafe dynamic evaluation | S/I | Source/isolated fixture |
| WEB-06.11 | Check header injection, CRLF, open redirect and host-header trust | U/I | Bounded staging test |
| WEB-06.12 | Check regex/algorithmic complexity and request-size limits without DoS | S | Static cost and limit proof |
| WEB-06.13 | Check CSV/formula injection in export workflows with synthetic data | U | Test-only CSV |
| WEB-06.14 | Check exception handling for stack traces, secrets and partial transactions | U | Safe handled-error paths |
| WEB-06.15 | Validate upload type, content, size, retention and execution boundaries | S/U | Approved safe test file |
| WEB-06.16 | Verify content-type, charset and MIME sniffing protections | B/U | Header and response context |

## WEB-07 — REST APIs, GraphQL, WebSockets and integrations

*Crosswalk: OWASP API Security Top 10:2023, WSTG 4.4/4.5/4.7.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-07.01 | Reconcile OpenAPI/GraphQL schema and actual deployed API revision | S | Published spec/build and schema |
| WEB-07.02 | Verify API object- and property-level authorization | U | Synthetic actor/object matrix |
| WEB-07.03 | Verify API function-level role checks and disabled accounts | U | Safe denied/allowed cases |
| WEB-07.04 | Verify pagination, export, filter, ordering and count authorization | U | Tenant-scoped fixture |
| WEB-07.05 | Verify rate limits/quotas and bounded work per request | S/U | Config and controlled sample |
| WEB-07.06 | Verify GraphQL introspection, query depth, batching and query cost policy | S/U | Production policy/test schema |
| WEB-07.07 | Verify WebSocket handshake identity, channels, per-message authorization | U | Authorized test messages |
| WEB-07.08 | Verify signed inbound webhooks, replay prevention and device identity | U | Staging callback fixtures |
| WEB-07.09 | Check API inventory drift, deprecated versions and exposed documentation | S | Route and deployment comparison |
| WEB-07.10 | Check unsafe consumption of partner API content, redirects and auth forwarding | S | Trust boundary review |
| WEB-07.11 | Verify CORS is appropriate to credentialed endpoints and origins | U | Known-origin browser tests |
| WEB-07.12 | Verify high-value API flows cannot bypass anti-automation protections | U | Synthetic quota checks |

## WEB-08 — Business logic and abuse cases

*Crosswalk: WSTG 4.10, ASVS business logic, OWASP Top 10 A06:2025.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-08.01 | Inventory account, approval, checkout, reward and fulfillment state machines | S | Documented workflow |
| WEB-08.02 | Verify flow steps cannot be skipped or reordered unsafely | U | Synthetic actor transitions |
| WEB-08.03 | Check duplicate submissions and idempotency on money/reward events | U | Test-only transaction receipts |
| WEB-08.04 | Review business-reference / receipt uniqueness and anti-replay constraints | U | Synthetic reference fixtures |
| WEB-08.05 | Verify cross-role segregation of approval, review and payout duties | U | Actor matrix |
| WEB-08.06 | Check inventory, pricing, discount and coupon integrity | U | Test products and carts |
| WEB-08.07 | Check race conditions only using safe small-scale concurrency in staging | I | Explicit bounded fixture |
| WEB-08.08 | Check reward/loyalty transfer rules and ownership evidence | U | Synthetic accounts |
| WEB-08.09 | Verify irreversible actions require appropriate confirmation and logging | S/U | Staging flow |
| WEB-08.10 | Review abuse prevention and anti-automation of sensitive economic flows | S/U | Documented controls |

## WEB-09 — Client-side and browser security

*Crosswalk: WSTG 4.11, ASVS web frontend security.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-09.01 | Review CSP directives against actual script/style use | B/S | Sanitized policy and source |
| WEB-09.02 | Inspect client-side DOM sinks, HTML injection and URL scheme validation | S | Source sinks and fixtures |
| WEB-09.03 | Validate messaging origins, `postMessage`, iframe and opener handling | S/U | Approved frame test |
| WEB-09.04 | Check open redirect from client-side routers and deep links | S/U | Route and safe test |
| WEB-09.05 | Verify third-party script inventory, integrity and update policy | S | Script list/asset hashes |
| WEB-09.06 | Check source maps and debug objects for sensitive release information | S | Build manifest |
| WEB-09.07 | Check offline cache/service worker and PWA credential leakage | S/U | Storage and update policy |
| WEB-09.08 | Review browser-side token/password persistence and refresh behavior | S/U | Storage schema |
| WEB-09.09 | Verify cross-origin resource/embedded content controls | U | Browser/network result |
| WEB-09.10 | Review client-side dependency vulnerabilities as distinct from runtime server exposure | S | Multiple dependency instances |

## WEB-10 — Sensitive data, privacy and disclosure

*Crosswalk: ASVS data protection, WSTG 4.2/4.8, OWASP Top 10 A04/A09:2025.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-10.01 | Review public static assets for personal/payroll/export/backup content | S | Filenames and owner-approved access |
| WEB-10.02 | Verify sensitive API responses are subject to object/tenant authorization | U | Synthetic data |
| WEB-10.03 | Verify protected endpoints never silently downgrade to URL-possession reads | S/U | Fallback and access policy |
| WEB-10.04 | Verify secrets aren't in HTML, JS bundles, configuration or URL query parameters | S | Redacted leak report |
| WEB-10.05 | Verify logs, errors and tracing redact credentials, tokens, PII and payment information | S | Logging policy and fixtures |
| WEB-10.06 | Verify sensitive browser/proxy cache controls and CDN cache keys | S/U | Authenticated test response |
| WEB-10.07 | Validate file object storage ACL, signed URL expiry and immutable keys | S/U | Test files and IAM |
| WEB-10.08 | Review encryption at rest and key separation for sensitive categories | S | Design/IAM evidence |
| WEB-10.09 | Verify retention/deletion requirements and privacy access logging | S/U | Policy and records |
| WEB-10.10 | Check accidental exposure of debug traces and internal host details | B/U | Sanitized error/headers |

## WEB-11 — File upload, third-party and platform security

*Crosswalk: WSTG config/input testing, ASVS file handling & communications, API10:2023.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-11.01 | Confirm extension+MIME+content validation for uploads | S/U | Source and benign fixture |
| WEB-11.02 | Enforce safe names, download disposition and antivirus/scanning where required | S | Storage policy |
| WEB-11.03 | Prevent executable upload exposure and unsafe direct object storage | S | Serving config |
| WEB-11.04 | Verify object ACL and authorization for user uploads and employee documents | U | Two synthetic users |
| WEB-11.05 | Verify webhook/API token scope, timeouts and retry replay resistance | S/U | Integration tests |
| WEB-11.06 | Review third-party payment/identity redirects without probing the vendor | S/U | Client-owned flow boundaries |
| WEB-11.07 | Verify outbound allowlisting, SSRF controls, DNS pinning and response size budgets | S | Network and parser policy |
| WEB-11.08 | Ensure no cross-environment secrets/data replicate between prod, UAT and dev | S | Secrets and tenancy audit |

## WEB-12 — Deployment, dependencies, observability and recovery

*Crosswalk: OWASP Top 10 A02/A03/A08/A09/A10:2025 and shared Witch Dog checklist.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-12.01 | Compare public origin to actual ingress (CDN/Compose/K8s) and artifact release | S | Running route/digest |
| WEB-12.02 | Detect exposed dev servers, console, debug endpoints and unsafe default binds | S | Live listener and reachability |
| WEB-12.03 | Audit **each** direct/transitive dependency instance against advisories | S | Resolved graph/SBOM |
| WEB-12.04 | Check affected-version AND exploit prerequisite AND running reachability | S | Advisory predicate matrix |
| WEB-12.05 | Verify NGINX and NGINX Ingress Controller as **separate products** | S | Actual version/vendor config |
| WEB-12.06 | Verify host-published database/metrics/debug ports aren't externally exposed | S | Effective bind/firewall |
| WEB-12.07 | Verify placeholder and default credentials are never active (no value logging) | S | Secure config attestation |
| WEB-12.08 | Ensure immutable images, protected branches and CI provenance | S | SHA/digest/signature |
| WEB-12.09 | Check SIEM/EDR logs alert on authz abuse, suspicious process tree and key changes | S | Detection tests |
| WEB-12.10 | Validate backup/restore, admin access and incident containment readiness | S | Exercise record |

## WEB-13 — Reporting, remediation and retest gates

*Crosswalk: NIST SP 800-115 report/mitigation, WSTG reporting, ASVS verification discipline.*

| ID | Test objective | Tier | Required evidence |
|---|---|---|---|
| WEB-13.01 | Record exact authorized origins, test window, tester/tool/model identity | B | RoE + run metadata |
| WEB-13.02 | Record scope exclusions, HTTP request count and full coverage gaps | B | Run manifest |
| WEB-13.03 | Keep sanitized evidence and hashes in tenant-private storage | B | Evidence digest |
| WEB-13.04 | Separate observed config, suspected risk, confirmed flaw and untested control | B | Confidence and verdict |
| WEB-13.05 | Risk-rank by impact, exposure, KEV/EPSS and prerequisites, not CVSS alone | S | Relevant context |
| WEB-13.06 | Pair findings with reproducible, safe retest criteria and owner | B | Remediation ticket |
| WEB-13.07 | Require independent review of AI triage and false-positive/negative test cases | S | Review record |
| WEB-13.08 | Restrict security remediation to reviewed source PRs; no silent prod changes | S | Approved PR and CI |
| WEB-13.09 | Reverify running release/behavior, not just merged Git commit | S | Authorized post-deploy evidence |
| WEB-13.10 | Preserve `UNKNOWN` where no live access, auth credentials or invasive authorization | B | Deferral matrix |

## Default BASELINE coverage map

A single request to `/` can **only** support a small, explicitly enumerated set: `WEB-00.01` as operator attestation, `WEB-01.01` DNS class, `WEB-01.03` response/redirect, `WEB-02.01` HTTPS certificate validity, `WEB-02.03`–`WEB-02.09` selected header presence, and `WEB-05.01` cookie *flag metadata*. Some checks depend on response availability.

All other catalog entries must remain `UNKNOWN / NOT_RUN`, unless there is additional authorized evidence. **Never report an overall “WSTG PASS”, “ASVS L1 PASS” or “VAPT passed” based on this baseline.**

## Suggested professional report structure

1. Engagement / explicit authorization and out-of-scope assets
2. Executive summary and high-confidence confirmed risks
3. Architecture and asset context: source vs edge vs running deployment
4. Methodology/standards and test tools + versions
5. Detailed findings: ID, affected endpoint (redacted), severity and confidence, proof class, user/business impact, safe reproduction, fix and owner
6. Controls executed vs deferred, including rationale for `UNKNOWN`
7. Remediation actions that require human authorization; source PR links where applicable
8. Post-deploy retest results and closure evidence
9. Appendix: non-sensitive hashes, UTC timestamps, versioned standards and evidence handling

Keep detailed reports and raw test data **outside this public GitHub repository**. Store client evidence privately and do not transmit private data to external model providers without client consent.
