# ARTEX research for Witch Dog

This review covers two public ARTEX variants as of November 20, 2026.

- BaaRai ARTEX: https://github.com/BaaRai/ARTEX
- ARTEX Global: https://github.com/jiwoochris/artex-global

Both projects identify their license as AGPL-3.0. Witch Dog uses MIT.

This document describes design ideas. It does not copy ARTEX code.

## What ARTEX does

ARTEX separates a task into a plan and multiple worker intents.

The planner reads current results. It creates more tasks when a result needs more work.

Workers execute tools and record results. The system keeps a link between an asset, a test, and its evidence.

ARTEX uses two connected graphs. One describes assets. The other describes tests and progress.

ARTEX also uses scope checks, approval gates, task limits, and a record of test coverage.

The global variant includes defense and detection rules. It tests whether these rules match their source references.

## Witch Dog decisions

| Design | Decision | Reason |
|---|---|---|
| Planner roles | ADD | Separate planning from tool execution. |
| Asset and test records | ADD | Keep each test linked to an approved asset. |
| Coverage ledger | ADD | Keep a record of tests and unknown results. |
| Evidence references | KEEP | Do not claim a finding without evidence. |
| Budget control | EXPAND | Limit time, requests, agent calls, and model tokens. |
| Shared worker memory | PLAN | Reuse checked facts without sharing raw secrets. |
| Detection rule tests | PLAN | Add safe defensive rules with test cases. |
| Autonomous attack chains | DO NOT COPY | Require approved scope and independent safety checks. |
| Web console and database | DEFER | Keep the current Python CLI simple. |

## Current implementation

The offline planner creates a list of test intents.

It uses the approved Witch Dog engagement file. It does not execute a test.

The coverage ledger records the result of a test. It needs evidence for a reported finding or a negative result.

A test is not a PASS only because no finding exists.

Run these commands with a private approved engagement.

    python3 tools/agent_plan.py init --scope PATH_TO_ENGAGEMENT --out .witchdog/plan-01
    python3 tools/agent_plan.py record --out .witchdog/plan-01 --surface /approved/test --area authorization --outcome NEEDS_FOLLOWUP

The second command records a coverage gap. It does not contact a website.

## Agent responsibilities

| Role | Responsibility |
|---|---|
| PLANNER | Select the next safe test from known gaps. |
| COLLECTOR | Run a deterministic tool in approved scope. |
| INVESTIGATOR | Study evidence and form a test hypothesis. |
| VERIFIER | Check the hypothesis with independent evidence. |
| REPORTER | Record findings, limits, and open questions. |

A future coordinator can assign these roles to different models.

The runner must enforce approval, network limits, and tool permissions outside the model.

## Exit rules

- Stop a stage when it has no approval.
- Stop a stage when it exceeds a budget.
- Reject tool output that is outside the approved scope.
- Keep unknown controls visible.
- Keep raw credentials and personal data out of agent context.
- Send source fixes through a reviewed pull request.
- Verify each fix on the running test application.

## License note

Both ARTEX variants use AGPL-3.0. Do not copy their implementation into Witch Dog.

Use the public architecture as a research reference. Review any future code reuse with a license specialist.

## Reference files

- BaaRai ARTEX README and agent/planner.go
- BaaRai ARTEX agent/coverage_ledger.go
- BaaRai ARTEX agent/budget.go
- BaaRai ARTEX agent/untrusted_boundary.go
- ARTEX Global detections/README.md
- ARTEX Global MAINTAINING.en.md
