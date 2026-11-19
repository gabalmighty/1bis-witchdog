# Website baseline pilot lessons — 2026-11-19

This is a **genericized** Witch Dog improvement record from two operator-supplied BASELINE runs. Client/customer names, private paths, DNS records, scan evidence and prior Critical details are deliberately omitted. It is **not** a new vulnerability report.

## Pilot comparison (operator-supplied, not live independently re-tested)

| Observable | Website A (protected business app) | Website B (informational site) |
|---|---|---|
| Root response | 200 | 200 |
| TLS negotiated | TLS 1.3, trusted chain | TLS 1.3, trusted chain |
| HSTS | Missing on root | Present, below a six-month baseline |
| CSP | Missing on root | Present with no obvious unsafe inline/eval source |
| X-Content-Type-Options | Missing | Present |
| Framing policy | Missing | Present |
| Referrer-Policy | Missing | Present |
| Permissions-Policy | Missing | Present |
| Authentication/authorization/tenant isolation | UNKNOWN | UNKNOWN |
| APIs, sensitive data, business logic | UNKNOWN | UNKNOWN |

The reports were generated in different amounts of AI processing time. Both were based on **one root request**, and therefore tested the same narrow surface. One completed in under a minute and the other in about two minutes. Duration is not an independent quality metric.

## False confidence to prevent

1. **No Critical finding detected** from one GET does not mean that none exists. Historical unresolved findings are carried forward separately and cannot be superseded by a later header-only result.
2. **CSP present** does not mean scripts are constrained: `img-src` only, an empty policy, a broad `script-src *`, `https:`, `data:`, `'unsafe-inline'` or `'unsafe-eval'` require review. Even a structurally strong CSP does not prove XSS absence.
3. **X-Frame-Options present** does not mean clickjacking is mitigated: `ALLOW-FROM` is obsolete; `frame-ancestors *` is broad.
4. **Header value matters:** `notnosniff` is not `nosniff`, and `Referrer-Policy: unsafe-url` may increase leakage compared with the modern browser default.
5. **Permissions-Policy** is not a blanket security score. It needs app-specific purpose and denies or scoped grants for powerful browser features.
6. **TLS 1.3 negotiated** proves only one successful TLS negotiation, not that deprecated versions/ciphers are disabled. Missing HSTS does not establish a reachable HTTP-only endpoint or that an attacker could strip the initial connection; review redirects and preload separately.
7. **Source and live edge may differ:** protections recorded in API middleware may not appear on the SPA root served by a separate reverse proxy/CDN. Mark `CONFLICTING` and require per-route deployed evidence.
8. **Schema validated** shows only a bounded report structure; it does not prove findings accurate or comprehensive.
9. **HTTP 401/403/429/503** can be a reverse proxy/WAF/auth response; it is a WARN / visibility gap, not a successful application security assessment.
10. **Nothing retrieved beyond the authorized root** implies all other route-specific protections, API access, session controls and business flows are UNKNOWN.

## Engineering changes

- Parse policy values for script-src/default-src, framing rules, exact nosniff, Referrer-Policy and sensitive feature grants.
- Avoid overclaiming HSTS/TLS and missing optional headers.
- Return `assurance=NOT_A_VAPT` plus an explicit high-impact UNKNOWN matrix; keep schema compatibility with legacy v0.1 reports.
- Preserve source/runtime/edge contradictions and prior report status outside the public repo.
- Add negative regression fixtures, including permissive CSP, obsolete XFO, weak Referrer-Policy, wildcard Permissions-Policy and WAF/auth response codes.
- Keep one-request default, DNS-pinned connection, private report location, no redirects/HTML body, and explicit authorization requirement.

## Next validation gate

Qualify against synthetic fixtures and on Windows/Ubuntu CI, then conduct operator-approved dual-vantage baseline on one UAT origin. Confirm that a known weak header causes WARN and a known narrow value causes PASS; verify that absent authorization blocks traffic. For higher confidence, add an **opt-in CONTROLLED_UAT** mode with synthetic roles and a signed test scope, rather than silently expanding the default production crawl.

## Primary interpretation references

- MDN CSP: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy
- MDN Referrer-Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy
- MDN X-Frame-Options: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options
- MDN Permissions-Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy
- MDN HSTS: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security

No customer data or credentials were incorporated into this document.
