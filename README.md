<p align="center"><img src="assets/witchdog-mark.png" alt="Witch Dog logo" width="170" /></p>

<h1 align="center">Witch Dog</h1>

<p align="center"><strong>Agentic Security. Continuous Vigilance.</strong></p>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Project stage](https://img.shields.io/badge/stage-experimental-orange.svg)](#project-status)
[![Quality tests](https://github.com/gabalmighty/witchdog/actions/workflows/quality.yml/badge.svg)](https://github.com/gabalmighty/witchdog/actions/workflows/quality.yml)
[![Intelligence](https://github.com/gabalmighty/witchdog/actions/workflows/intelligence.yml/badge.svg)](https://github.com/gabalmighty/witchdog/actions/workflows/intelligence.yml)

Witch Dog joins deterministic security tests with AI investigation.

Use the tools on an approved host, a set of Git repositories, or a test web application.

The tools record findings, test scope, and missing evidence. They do not certify that a system is secure.

## Quick start

Install Python 3.11 or later and Git. OpenCode is optional.

Clone Witch Dog next to the repositories that you want to review.

```text
workspace/
  witchdog/
  project-a/
  project-b/
```

```bash
git clone https://github.com/gabalmighty/witchdog.git
cd witchdog
python3 tools/witchdog.py scan --root .. --output .witchdog/runs
```

On Windows, use `py -3` instead of `python3`.

To use an agent, run this command from the Witch Dog folder.

```bash
opencode run --agent witchdog --model opencode-go/hy4-flash-free "Follow PROMPT.md. Audit this host and the Git repositories under .. . Start with read-only tests. Record evidence, gaps, and proposed fixes. Ask before any source change."
```

Verify that the model is available before you run it.

## Web application security tests

Use [the web prompt](web_prompt.md) for a website that you are authorized to test.

The default baseline sends one request. It checks transport and selected response headers.

The advanced VAPT mode can use OWASP ZAP in a controlled test environment.

Before an active test, approve the scope. Use synthetic data and a restricted network.

The agent must not bypass a failed tool gate.

[Read the VAPT guide](docs/vapt-execution.md) and [security checklist](checklists/webapp-vapt-v1.md).

## Pull request security review

Witch Dog can review code changes in GitHub Actions or on a local CI machine.

Start with [the setup prompt](review_setup_prompt.md). Let your coding agent select the correct method.

The [sample GitHub workflow](examples/witchdog-github-review.yml) uses a reviewed Action commit.

Use the [Linux](examples/witchdog-local.sh) or [Windows](examples/witchdog-local.ps1) script for local CI.

A free OpenCode model is optional. Confirm the model's data policy before you send private code.

[Read the PR review guide](docs/pr-review.md).

## Security intelligence

Witch Dog reads approved public feeds, including Cloudflare Zero Wire and CISA KEV.

GitHub Actions checks the feeds twice each day. New data goes into a review pull request.

The planned times are 08:31 and 20:31 in Asia/Manila.

The schedule has not yet passed its first live scheduled-run test.

[View the workflow](.github/workflows/intelligence.yml) and [check its status](docs/intelligence-operations.md).

Use an independent CI machine to detect a missed scheduled run.

```bash
python3 tools/intel_health.py --max-age-hours 16
```

## Agent planning and coverage

Witch Dog can prepare a test plan for an approved VAPT engagement.

The planner does not send requests or run tools. It names required tests and blocked stages.

The coverage ledger requires evidence before it records a finding or a negative test result.

[Read the ARTEX research](docs/artex-research.md) and [writing rules](docs/writing-standard.md).

## Feed the Witch Dog

Witch Dog improves through tested information from its community.

Share a reliable security feed. Add a test. Report a bug. Propose a safer workflow.

Do not post private client data, secrets, or live exploit evidence.

**[Read how to contribute](CONTRIBUTING.md).**

## Project status

Witch Dog is experimental. Some controls need a human reviewer or a controlled test environment.

A short baseline does not replace a full VAPT. A source-code fix does not prove a deployed fix.

Do not run active tests against systems without written authority.

The project uses the [MIT license](LICENSE). Third-party project names remain their owners' property.

[Security policy](SECURITY.md) · [Project architecture](docs/architecture.md) · [Agent instructions](AGENTS.md)
