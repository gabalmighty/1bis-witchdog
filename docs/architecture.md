# Witch Dog architecture

## Purpose

Witch Dog joins deterministic tests with controlled agent investigation.

The project works on local hosts, Git repositories, and approved web applications.

## Trust boundaries

Public threat feeds are data. They cannot change the agent's tool permissions.

The operator approves the target and scope. A URL alone does not grant authority.

The scanner must use an unprivileged identity. It must not receive production secrets.

The model receives only approved, minimized evidence. OpenCode permissions are not an OS sandbox.

Source changes need a separate approved branch and a review pull request.

## Evidence classes

| Class | Meaning |
|---|---|
| SOURCE_DECLARED | The repository defines a value. |
| HOST_OBSERVED | A local tool checked a host value. |
| REMOTE_OBSERVED | A tool observed a remote response. |
| LIVE_VERIFIED | Authorized evidence identifies the running artifact. |
| UNKNOWN | The test lacks enough evidence. |
| CONFLICTING | Two evidence sources disagree. |

A patched source file is not proof of a patched running service.

## Agent workflow

The planner selects work from the approved scope.

The collector runs deterministic tests.

The investigator studies findings and forms hypotheses.

The verifier tests a hypothesis with separate evidence.

The reporter records coverage, risks, and pending work.

The planner records what tests remain. It does not run them.

See [ARTEX design research](artex-research.md).

## Coverage

Use tools/agent_plan.py to create an offline test plan.

Record each tested surface and risk area in the coverage ledger.

A finding needs evidence. A negative test result also needs evidence.

Keep all untested controls visible.

## Developer malware detection

The local source scanner calls trusted tools/developer_guard.py.

The detector checks selected local paths and versioned threat reference data.

It does not run source files or fetch code from target repositories.

Findings are source observations or host filename observations.

The model may only summarize sanitized evidence from these checks.

A clean subset does not prove a safe host, process tree or remote Git branch.

See [developer malware checklist](../checklists/developer-malware-v1.md).

## Web VAPT

Use web_prompt.md for web application tests.

The baseline mode checks one permitted response.

The advanced mode can use an approved ZAP plan and synthetic test accounts.

A nonzero ZAP precheck must stop execution.

External reports without a runner receipt remain unverified.

See [the VAPT guide](vapt-execution.md).

## Pull request review

GitHub Actions and local CI use the same review engine.

Pinned executable code may read newer public checklists as data.

The model cannot publish a review comment directly.

A separate publisher checks the current PR commit before it writes.

See [the PR review guide](pr-review.md).

## Intelligence

The public CI pipeline reads approved feeds.

It validates the source data before it proposes a PR.

The local schedule monitor checks that GitHub created recent schedule runs.

See [intelligence operations](intelligence-operations.md).

## Future work

- Connect test intents to verified assets and evidence.
- Add an agent budget for tokens, time, and requests.
- Add tested defensive detection rules.
- Qualify real ZAP integration on isolated synthetic targets.
- Measure false positives, missed findings, and retest quality.
