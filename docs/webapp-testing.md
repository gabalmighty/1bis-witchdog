# Website / WebApp assessment operating guide

**Witch Dog WEB-01, experimental.** A lightweight black-box baseline is an appropriate starting point for owned websites, not a complete VAPT or audit attestation.

## What the URL scanner actually does

- Requires `--target` and `--authorized`; validates the URL and tests a single origin.
- Rejects unsafe URL syntax, embedded credentials, fragments/queries, private and loopback IPs by default, redirects to new destinations, and any DNS answer outside the allowed network class.
- Performs **one GET request to `/` only**; no follow-up on redirects, no spiders, no authentication or parameter injection.
- Inspects TLS handshake validity (HTTPS) and selected HTTP response headers; summarizes cookie **flag presence, never values**.
- Records `REMOTE_OBSERVED` for what the edge responded with, and `UNKNOWN` for untested authorization, app routes, origin build, ingress and storage.
- Returns a local `report.json` and `report.md` under the operator's explicit output directory. Private customer evidence belongs there, not in this public Git repository.
- The baseline is **not** a port, vulnerability or malware scan. Browser, JS, GraphQL, WebSocket, API, active payload and authentication tests remain separate.

## Quick start

```bash
# From Witch Dog's checkout, with an authorized HTTPS website:
python3 tools/web_baseline.py --target https://staging.example.org --authorized --output .witchdog/web-runs

# Windows:
py -3 tools/web_baseline.py --target https://staging.example.org --authorized --output .witchdog/web-runs
```

For internal, explicitly authorized labs only:

```bash
python3 tools/web_baseline.py --target http://127.0.0.1:8080 --authorized --allow-private --allow-http --output .witchdog/web-runs
```

The lab switches are deliberate and should not be baked into unattended production schedules. The scanner checks only the specified origin. Reject a publicly accessible reverse proxy that redirects to an internal host; do not auto-follow. A public CDN/WAF header observation is *not* proof of the private origin's security.

### Prompt invocation

```bash
opencode run --agent witchdog --model opencode-go/hy4-flash-free "Follow web_prompt.md. Target: https://staging.example.org. I am authorized to test this exact origin. Run BASELINE only. Use the full webapp checklist; explicitly mark controls not tested as UNKNOWN. Do not modify production or run active VAPT."
```

Because `web_baseline.py` accepts a dynamic target, OpenCode may ask to approve the command under its shell policy. That approval is for the exact bounded command, not permission for arbitrary tools. Do not globally allow arbitrary shell commands.

## Rules-of-engagement (RoE) template

Keep the written record **privately**, next to the target report:

| Field | Required |
|---|---|
| Owner/operator and written authorization | Yes |
| Exact origins and path scope | Yes |
| Production versus UAT | Yes |
| Testing period/timezone, emergency contact | Yes |
| Baseline request ceiling and rate limit | Yes |
| Allowed authentication identities and synthetic records | For controlled UAT only |
| Forbidden paths and irreversible operations | For controlled UAT only |
| Explicit consent for active exploitation or fuzzing | For invasive VAPT only |
| Isolation, backup, restore, rollback and evidence retention | For invasive VAPT only |

An owner's domain does not imply authorization to test shared provider infrastructure, vendor APIs, other tenants, third-party payments or linked destinations.

## Professional evidence conventions

- Use `REMOTE_OBSERVED` for HTTP/TLS facts returned by the network endpoint.
- Use `SOURCE_DECLARED` for code, lockfile and IaC facts.
- Use `LIVE_VERIFIED` only with trusted authenticated proof of the deployed runtime, not because a response includes `Server: nginx`.
- A root 200 does not show route-level auth, data isolation, input validation or business logic security.
- A missing header may be a **hardening observation**, not automatically a critical vulnerability.
- HTTP/2, HTTP/3, CDN bypass, origin security, rate limits and session integrity are **UNKNOWN** without suitable tests.
- A WAF challenge or anti-bot response means `BLOCKED`, not “protected” and not “exploitable.”
- Evidence should be minimized; don't store response bodies, secret values, session cookies, credentials or personal data.
- Record URL scope (without credentials or query parameters), timestamp, tool version, checklist revision and objective result.

## Scan status and severity

`PASS` means one specific test met expectations. `WARN` means the tester should review. `FAIL` needs demonstrated, relevant security control failure. `UNKNOWN` includes skipped, inaccessible, contradictory or insufficient results. `N/A` requires evidence of non-applicability. Severity is separately assigned from technical status using context, actual exploit prerequisites, exposure and business impact.

### Levels and schedule

`BASELINE`: periodic light checks of approved root endpoints; appropriate for low-impact scheduling after authorization.

`CONTROLLED_UAT`: dedicated test roles, object/tenant authorization matrix, auth/session, API flows, CSRF and account lifecycle tests. Use **synthetic** data, carefully bounded route lists, rollback plans and signed scopes.

`INVASIVE_VAPT`: active OWASP ZAP / Burp / specialist manual exploitation in isolated staging only, with explicit owner authorization and test windows. Do not schedule automatically as part of baseline. Spiders and other discovery can trigger unintended application writes, even when they use GET.

## Standards and references

- WSTG v4.2 (versioned): https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/
- ASVS 5.0.0: https://asvs.owasp.org/
- OWASP Top 10:2025: https://top10.owasp.org/2025/
- OWASP API Security Top 10:2023: https://api-security.owasp.org/editions/2023/en/0x00-header/
- OWASP ZAP Baseline: https://www.zaproxy.org/docs/docker/baseline-scan/
- OWASP ZAP safety: https://www.zaproxy.org/faq/is-there-any-danger-when-scanning-with-zap-against-a-live-website-e-g-create-delete-update-corrupt-data/
- NIST SP 800-115: https://csrc.nist.gov/pubs/sp/800/115/final

These sources inform the original Witch Dog checklist. No external standard or security company endorses or certifies Witch Dog.
