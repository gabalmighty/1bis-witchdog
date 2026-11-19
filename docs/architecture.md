# Witch Dog architecture and trust model

## Design decisions

- **One prompt + one checklist.** Applicability is selected from evidence, not a guessed platform. The Python scanner captures reproducible local facts; the AI performs contextual analysis and suggests targeted tests.
- **Separate public intel from private assets.** GitHub Actions fetches public advisories centrally. Client machines keep inventory and findings private; this public repo must not become a central client evidence database.
- **Scan is not repair.** Local read-only collection and AI analysis run at lower privilege. Source modifications, PR publication, service restarts and deployment use separate authorization.
- **Source vs running environment.** `SOURCE_DECLARED` (Dockerfile/manifest), `HOST_OBSERVED` (local OS), `LIVE_VERIFIED` (authenticated deployed image/config), `UNKNOWN` (insufficient evidence). Never promote one class to another.
- **Model agnostic.** AI provider routes may be chosen per tenant, sensitivity, latency and quality; record model/version, prompt/knowledge version and evidence digests. Deterministic checks remain model independent.

## Trust boundaries

1. Public RSS/JSON: HTTPS, source allowlist, response size/time limits, schema validation and escaping. Treat all text as untrusted data. Never execute feed content or let it mutate prompt/tool policy.
2. Local inspector: normal unprivileged user, explicitly bounded directory, no symlink traversal, no secret values, no host process/service mutation, no remote probes. The shipped inspector does not make a live vulnerability assessment.
3. AI worker: sanitized/minimized evidence, approved model provider, ephemeral isolated execution when possible, no privileged host mounts, no production network, no client credentials, no unattended shell.
4. Git fixes: per-target-repo branch and tests, reviewed PR, separate deploy approval, post-deploy running-image verification; no auto-merge.
5. Customer tenancy: encrypt/private-store sensitive evidence; retain hashes/metadata for audit; do not publish private findings to Witch Dog.

## Suggested expansion

Phase 1: deterministic discovery + public-feed updates + one prompt (shipped bootstrap).
Phase 2: SBOM scanners (Syft/Trivy/OSV), verified deployed runtime evidence, source-code SAST, local secure evidence store.
Phase 3: optional hardened OpenCode research CI using sanitized feed deltas and no write token; independent validation; reviewed PR.
Phase 4: preflight-gated disposable VM execution and tenant-specific PRs, secure escrow for artifacts, enforced cleanup.
Phase 5: multi-client management, controls dashboard, monitored drift and independently verified remediation.

## Threats explicitly addressed

Prompt injection via vendor RSS, malicious dependency install scripts, infected Git hooks/branches, shell injection from file names, accidental publication of credentials, recursive scanning outside scope, public GitHub runner exposure, model hallucination of deployed state, false PASS on missing evidence, and a remediation bot reintroducing a vulnerable state.

Read [PROMPT.md](../PROMPT.md) and [checklist](../checklists/security-v1.md) for execution rules.
