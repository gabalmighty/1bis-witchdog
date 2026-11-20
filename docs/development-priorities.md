# Witch Dog development priorities

Status: November 20, 2026. The review covered 14 open GitHub issues.

Use separate branches and reviewed pull requests for each workstream.

## Priority 0 — Reliability and secret exposure

| Issue | Work | Next action |
|---|---|---|
| [#21](https://github.com/gabalmighty/witchdog/issues/21) | Complete CISA KEV feed and scheduled PR delivery | Store all KEV entries. Verify an actual scheduled run. |
| [#24](https://github.com/gabalmighty/witchdog/issues/24) | Scan current and historical Git secrets | Build a pinned offline scanner adapter with private, redacted evidence. |

Do not mark the feed scheduler as verified after only a manual run.

Do not mark secret scanning as PASS when only file names were checked.

## Priority 1 — Accurate security evidence

| Issue | Work | Dependency |
|---|---|---|
| [#25](https://github.com/gabalmighty/witchdog/issues/25) | Scan locked dependency versions | Complete feed storage and reviewed offline database. |
| [#26](https://github.com/gabalmighty/witchdog/issues/26) | Add source, CI and infrastructure rules | First, cover all Docker base images. |
| [#10](https://github.com/gabalmighty/witchdog/issues/10) | Verify real ZAP behavior | Use an isolated app with synthetic records. |
| [#14](https://github.com/gabalmighty/witchdog/issues/14) | Validate the PR reviewer with real models | Use a disposable public test repository. |
| [#27](https://github.com/gabalmighty/witchdog/issues/27) | Match advisories to assets | First, add verified dependency identifiers. |
| [#11](https://github.com/gabalmighty/witchdog/issues/11) | Test authenticated API authorization | Use qualified ZAP, safe user fixtures and reversible requests. |
| [#4](https://github.com/gabalmighty/witchdog/issues/4) | Collect host and runtime evidence | Test Windows and Linux in isolated VMs. |

The source scanner does not prove that a deployed image is vulnerable.

The VAPT test must not change production data.

## Priority 2 — Platform expansion

| Issue | Work |
|---|---|
| [#5](https://github.com/gabalmighty/witchdog/issues/5) | Provision disposable VMs with cleanup proof. |
| [#22](https://github.com/gabalmighty/witchdog/issues/22) | Build an evidence-linked multi-agent test coordinator. |
| [#3](https://github.com/gabalmighty/witchdog/issues/3) | Propose fixes in each approved target repository. |
| [#15](https://github.com/gabalmighty/witchdog/issues/15) | Add deeper review context and safe fork PR support. |

Do not start unattended source fixes before the isolation and review gates work.

## Priority 3 — Optional research

| Issue | Work |
|---|---|
| [#6](https://github.com/gabalmighty/witchdog/issues/6) | Add optional multi-model public threat research. |

Keep the deterministic feed pipeline independent of model availability.

## Delivery policy

Each coding agent receives one issue and one branch.

The agent must read AGENTS.md and the relevant checklist.

Use fixture data for testing. Do not use real keys or customer records.

Record tests, failure cases, known limits and exact changed files.

Never auto-merge an agent PR. Request an independent gatekeeper review.

Use [the compact agent work orders](agent-work-orders.md) to start development.
