# Witch Dog — Agentic VAPT execution guide (experimental)

**Version:** WEB-VAPT-ALPHA-01. This release adds ZAP tests, scope gates, synthetic role checks and agent review. It does not automate browser sessions, complex workflows, full discovery or a certified penetration test.

## ZAP validation, warning codes and external evidence (2026-11-20)

A passive pilot found that an installed ZAP Automation Framework rejected the generated Environment-level `maxDuration` option. Witch Dog now omits this compatibility-sensitive field and enforces an external subprocess timeout. New active spider plans also disable form POSTs and auxiliary sitemap/robots discovery by default. **The exact installed ZAP build and add-ons must still pass `-autocheck` and real lab qualification**.

A nonzero -autocheck returns HELD_PRECHECK_NONZERO. Do not bypass this gate. After a clean precheck, ZAP -autorun code 2 means warnings. A valid report and runner receipt are required for EXECUTED_WITH_WARNINGS. Other errors remain PARTIAL.

You can import a direct ZAP run for private review. Mark its evidence EXTERNAL_UNVERIFIED. Do not mark it EXECUTED by editing a manifest. The receipt binds scope, plan, report hashes and exit codes. It does not prove runner identity or network isolation.

The passive pilot checked one root endpoint with two tools: multiple header observations are not independent demonstrations of exploitability or extensive test coverage. Detailed lessons are in [generalized security audit handoff](security-lessons-20261120.md).

## Why the old report said NOT_A_VAPT

`web_baseline.py` v0.2.0 deliberately makes only one GET request. That can establish a few HTTP/TLS facts but cannot explore authentication, business logic, APIs, injection, sensitive data or tenant boundaries. We keep that deterministic safety probe as **Stage 0**, but do not call it the completed assessment.

Real professional VAPT uses a bounded **rules of engagement (RoE)**, tests deployed behavior, finds and verifies risks, and documents what remains untested. An external domain that looks like staging is **not evidence** that data is synthetic or that the environment is isolated. Active scanners may cause writes, account lockouts, service load or unexpected downstream effects.

## Quick start — one prompt, with a private engagement

From Witch Dog's folder, use OpenCode:

```bash
opencode run --agent witchdog --model opencode-go/hy4-flash-free "Follow web_prompt.md. Target: https://staging.example.invalid. Mode: AGENTIC_VAPT. Use our private approved engagement. Run safe/authorized stages, verify security hypotheses with synthetic fixtures, combine ZAP and source review, produce a detailed findings and coverage report, and propose reviewable fixes. Stop any stage missing scope, backup, network guard or human authority."
```

The agent will look for the engagement file. If absent, the agent should create a draft and request owner approval **once** for all permitted stages. It must not mark approvals as true on the user's behalf.

### 1. Generate a draft (zero network activity)

```bash
python3 tools/vapt.py init --target https://staging.example.invalid --output .witchdog/vapt/my-engagement
```

On Windows PowerShell, use `py -3` in place of `python3`. The draft is saved to `.witchdog/vapt/my-engagement/engagement.json` and is **intentionally ineligible** for execution until the human validates the scope. This is a private, gitignored path.

Record the exact origin, owner, expiry, contact and approved paths in private storage. Record test accounts, synthetic fixtures, test limits and active-test approval. Verify target-only network access and the restore snapshot. Do not put credentials in JSON.

### 2. Make preflight and review the deterministic test plan

```bash
python3 tools/vapt.py preflight --scope .witchdog/vapt/my-engagement/engagement.json

python3 tools/vapt.py plan --scope .witchdog/vapt/my-engagement/engagement.json --output .witchdog/vapt/my-engagement/run-01
```

Preflight validates the engagement; plan writes a `zap-plan.yaml` and `manifest.json` with SHA-256 provenance (not publisher signatures). Neither command contacts the website.

- `mode: passive` seeds **explicitly approved GETs** through ZAP and runs passive rules, then writes a ZAP JSON report.
- `mode: active` adds a tightly bounded spider and ZAP `activeScan` to attack approved staging endpoints with actual security test inputs. Active scans can mutate data.
- The active policy uses a low default attack strength, one thread/host, request delays and a job-level duration limit. This **does not enforce an exact total HTTP request count**.
- Source/role fixtures are separate stages. Adding an OpenAPI spec, authenticated browser session, stateful test or other endpoint requires deliberate test scope and is not silently handled.

Before approving execution, review the generated plan and confirm the network isolation. **ZAP's context includePaths restricts scan targeting but does not substitute for a VM/network firewall that enforces the permitted destination.** The Python runner cannot prove the independent network guard from a JSON boolean.

### 3. Execute ZAP (only on the approved restricted runner)

Install and verify a trusted OWASP ZAP Automation Framework release **out of band**. Do not download/extract/execute an agent-supplied installer on a client host. Use a non-admin service identity in a disposable VM or isolated test container with target-only egress, no host Docker socket or client secrets.

```bash
python3 tools/vapt.py execute --scope .witchdog/vapt/my-engagement/engagement.json --output .witchdog/vapt/my-engagement/run-01 --approval-ref SEC-APPROVAL-123 --zap-bin zap.sh --ack-impact
```

Omit `--ack-impact` for passive scans; it is required for active scans. `--approval-ref` must exactly match the private engagement. Active mode also requires verified synthetic data, allowed routes, independent egress guard, and snapshot/restore attestation, recorded in that file.

On Windows, the ZAP launch may require an installed Windows ZAP command path (`--zap-bin zap.bat`) or a restricted Linux/WSL worker. The default runner **does not create a VM**. Running a privileged local ZAP process in the same host as production is not recommended.

The tool runs ZAP without a shell. It applies a process timeout and hides raw output. It holds execution when the scanner, permission, plan hash or approval is invalid. Each run needs a new output folder.

### 4. Convert raw alerts to privacy-minimized evidence

```bash
python3 tools/vapt.py ingest --scope .witchdog/vapt/my-engagement/engagement.json --output .witchdog/vapt/my-engagement/run-01
```

A raw ZAP report can contain sensitive request data. Never publish it or send it to an unapproved model. The ingest tool saves bounded alert names and counts without raw URLs or payloads. Review each candidate independently.

### 5. Run synthetic authorization checks

Configure `role_token_env` in the private scope, e.g.:

```json
"role_token_env": {"employee": "WITCHDOG_EMPLOYEE_TOKEN"},
"authz_cases": [
  {"id":"synthetic-self-record", "path":"/__security_test__/my-record",
   "method":"GET", "synthetic_fixture":true,
   "expected":{"anonymous":[401,403], "employee":[200]}}
]
```

Supply only **dedicated synthetic** test-user tokens using local OS/process environment variables, never in a prompt or public repository. For example, set the environment variable using your private operator/vault workflow.

```bash
python3 tools/vapt_authz.py --scope .witchdog/vapt/my-engagement/engagement.json --output .witchdog/vapt/my-engagement/run-01 --approval-ref SEC-APPROVAL-123 --confirm-synthetic
```

The matrix sends only the authorized GET paths, with explicit expected statuses per role, no redirects and no response-body reads. It produces `authz-status-matrix.json` with pass/mismatch/unknown for **configured synthetic fixtures only**. A status mismatch is **not automatically proven IDOR/BOLA**; reviewers must verify that the endpoint and test data were correctly classified.

Cookie-authenticated workflows, role transitions, in-browser behavior, CSRF, uploads, multi-step business logic and stateful authorization require another dedicated harness. They are on the implementation roadmap, not silently claimed as tested.

### 6. Agentic security analysis and fix/retest

After the deterministic phases, the coding agent:
- Reads the [identity and authorization checklist](../checklists/identity-authorization-v1.md), checking alternate sensitive routes, token issuers/relying services, per-request tenant policy and source-versus-runtime proof.
- Reads only sanitized scanner outputs plus authorized source files (never secrets).
- Builds a threat model and a matrix of routes/roles/objects/controls from actual architecture evidence.
- Correlates suspicious dynamic behavior with source code and any prior independently confirmed findings.
- Chooses minimally invasive synthetic reproduction tests for high-value scenarios. Separates candidate from independently verified exploitability.
- Produces a detailed tenant-private report including OWASP references, confidence, prioritization, coverage gaps, operational risks and proposed fixes.
- On explicit source-change approval, opens a new PR in the **target repo**, adds regression tests and waits for reviewer/deployment signoff.
- After the exact patched version is deployed, retests the runtime with the same synthetic fixtures.

**Never run destructive payloads or persistence, exfiltrate production data, attack adjacent tenant systems, or auto-merge/deploy.** A valid RoE is necessary, but does not make dangerous testing automatically safe.

## What counts as high-quality VAPT

| Capability | Current implementation | Verification still needed |
|---|---|---|
| Exact origin and explicit RoE | Gated engagement JSON + digest | Human evidence of authorization |
| HTTP/TLS baseline | Existing working tool | Per-route deployment differences |
| Passive dynamic analysis | OWASP ZAP Automation Framework plan/runner | Installed ZAP and approved target |
| Active injection exploration | Scoped ZAP spider/activeScan with caps | Isolated stage, network guard and safe fixtures |
| Multi-role authorization assertions | Deterministic GET status matrix | Synthetic fixtures, body-aware controlled UAT and manual triage |
| Source/dependency review | Existing agent+repo scanner | Authorized source and trained reviewer |
| Evidence privacy | Raw/private vs sanitized output separation | External provider DLP acceptance |
| Application workflow exploitation | **Design backlog**, not automated | Browser-based test harness + fixtures |
| Full manual penetration testing | **Not implemented** | Qualified human tester and comprehensive RoE |
| Verified remediation | PR+retest process documented | Running deployed artifact evidence |

Do not report `FULL_VAPT_COMPLETE` or `ASVS_L1_PASS` just because ZAP finished. Report **SCOPED_VAPT_PROGRESS** with what was actually executed and what remains unknown.

## Test target for engineering acceptance

Use OWASP Juice Shop or deliberately vulnerable synthetic in-house applications inside an isolated lab. Validate that an intentionally vulnerable reflected-input fixture produces an alert, authorization fixtures deny wrong roles, and a clean fixture is not falsely flagged. Record negative tests for out-of-scope redirects, a denied destination CIDR, missing approval, test expiration, mutated plan hashes, unavailable ZAP and malformed raw reports. Never use customer payroll/employee records as fixtures.

## Standards and tool docs

- [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [ZAP activeScan job](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/)
- [ZAP Automation Framework environment](https://www.zaproxy.org/docs/desktop/addons/automation-framework/environment/)
- [ZAP traditional JSON report](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/)
- [OWASP WSTG v4.2](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/)
- [OWASP ASVS](https://asvs.owasp.org/)
- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)

Witch Dog is independent open-source engineering, not an OWASP accreditation or a substitute for professional scope approval.
