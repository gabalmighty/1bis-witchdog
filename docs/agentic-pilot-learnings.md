# Agentic triage pilot — generalized lessons (2026-11-19)

Source: operator-provided read-only pilot summary for an application with two advisories and seven asset entries. **This document intentionally omits customer identity, private repository identifiers, hostnames and deployment details.** It is a checklist design input, not proof that the specific private deployments were safe or compromised.

## Verified observations in the supplied summary

1. An application's top-level development dependency resolved a **patched** version while its test runner transitively resolved a **different, affected version**. The assessment did not prove a vulnerable network-exposed test runner.
2. Development-server source configuration advertised a broad listening interface, but actual workstation installs and reachability were unverified.
3. A source Dockerfile did not ship certain development dependencies, yet the running image digest was not available.
4. An upstream web-server image was from an affected release family, while repository configuration appeared not to enable the relevant features. The actual running config and vendor build were unknown.
5. A similarly named ingress controller was a **different product/distribution**; its version and the actual ingress path had not been established.
6. Infrastructure declared host-published datastore/observability/debug ports and possible default values; whether they were externally reachable or running with placeholder credentials remained unknown.
7. The prototype used sanitized and SHA-256-hashed input manifests plus deterministic post-run validation — valuable architecture for an AI worker.
8. Runtime verification, KEV/EPSS enrichment and adversarial regression were absent. The worker was a read-only child session, **not a hardened disposable VM**.

## Resulting design decisions

| Lesson | Checklist / structure follow-up |
|---|---|
| Different resolved versions in dependency chains | B08: each distinct transitive instance and lockfile path is evaluated |
| Declared vs installed vs running versions | A08, B09: separate evidence classes and version provenance |
| Edge feature prerequisites | B10: protocol/module/listener/config prerequisite matrix |
| Multiple possible ingress implementations | A09: reconcile deployment topology; detect conflicting claims |
| Published ports / possible placeholder credentials | G08/G09: effective binding, reachability and secure default proof |
| Trustworthy AI triage | H11/H12: digest input, validated output and adversarial fixtures |
| LLM discussion not equivalent to live verification | H13: evidence-gated closure and verified runtime retest |
| Public repository vs private client | E07/H09: publish only sanitized/generalized lessons |

## Acceptance test ideas

- Fixture with two Vite versions, only one vulnerable, and distinct runtime reachability contexts.
- Configuration declaring edge disabled features while runtime remains absent: advisory applicability stays `UNKNOWN`.
- Compose and cluster descriptions disagreeing: explicit `CONFLICTING` instead of selecting one.
- Multiple CIDR/bindings behind a proxy: no assumption of external reachability from a compose `ports` line.
- Known placeholder credentials in templates: presence in a template is a **warning**, not proof the live service uses them.
- Adversarial HTML/JSON trying to override prompts or exfiltrate secrets: reject as tool instructions.
- No tests or scanner data: mandatory `UNKNOWN` for unchecked controls.

No runtime retest, attack, exploit execution, credential handling or customer-specific fixes were performed in preparing this design document.
