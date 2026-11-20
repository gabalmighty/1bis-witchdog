# Coding-agent work orders

Use one work order per coding-agent session.

Run each session in the Witch Dog repository.

Do not combine work orders in the same pull request.

## Issue #24 — Git secret-history scanner

**Priority:** P0. **Owner:** Coding agent with an independent security reviewer.

### GOAL

Find exposed secrets in tracked content, branch heads and Git history.

### INPUT

- [Issue #24](https://github.com/gabalmighty/witchdog/issues/24)
- Source: tools/witchdog.py
- Policy: checklists/security-v1.md, E01

### STEPS

1. Inspect the current scanner and known limits.
2. Design an optional adapter for a reviewed, pinned secret scanner.
3. Run it without downloading tools during a scan.
4. Check the worktree, index, branch heads and Git history separately.
5. Bound execution time, repository size and finding count.
6. Remove all raw values before reporting.
7. Create synthetic history and clean negative fixtures.
8. Test on Windows and Ubuntu.
9. Open a PR with source evidence and safe rollback.

### GATES

No raw secret can enter a model, log or public PR.

Missing tools or incomplete history must yield UNKNOWN or PARTIAL.

Do not execute Git hooks or target source scripts.

### OUTPUT

A reviewed scanner adapter, tests and private report schema.

## Issue #25 — Lockfile vulnerability matcher

**Priority:** P1. **Owner:** Coding agent with dependency-security reviewer.

### GOAL

Match resolved package versions to an offline advisory database.

### INPUT

- [Issue #25](https://github.com/gabalmighty/witchdog/issues/25)
- Policy: checklists/security-v1.md, B02 and B08
- Feed: data/intel/latest.json

### STEPS

1. Identify supported lockfile formats.
2. Choose a pinned, offline-capable matching engine.
3. Record database version, date and age.
4. Parse resolved versions without package installation.
5. Preserve direct and transitive dependency paths.
6. Match affected ranges and fixed releases.
7. Report SOURCE_DECLARED, not deployed vulnerability proof.
8. Test vulnerable, patched, missing and malformed fixtures.
9. Open a PR with measured false-positive cases.

### GATES

Do not download a new vulnerability database during private scans.

Do not claim PASS when a scanner or database is missing.

Do not run package lifecycle scripts.

### OUTPUT

Offline matching adapter, schema and cross-platform tests.

## Issue #26 — Source and CI security checks

**Priority:** P1. **Owner:** Coding agent with CI security reviewer.

### GOAL

Extend source rules to workflows, Compose and Kubernetes.

### INPUT

- [Issue #26](https://github.com/gabalmighty/witchdog/issues/26)
- Policy: checklists/security-v1.md, F04 through F06
- Existing Docker base-image improvements on main

### STEPS

1. Inspect the current F06 rule and tests.
2. Detect unsafe workflow permissions and unpinned actions.
3. Detect privileged containers and unsafe host mounts.
4. Detect exposed debug ports in declared configurations.
5. Keep source-only observations separate from runtime results.
6. Test a safe and an unsafe fixture for each rule.
7. Add an optional pinned SAST adapter.
8. Open a reviewed PR.

### GATES

Do not execute configuration files.

Do not run SAST when its binary or rules are unverified.

Do not imply that source declarations prove host exposure.

### OUTPUT

New rule IDs, tests, risk notes and fixture coverage.

## Issue #10 — Real ZAP qualification

**Priority:** P1. **Owner:** Coding agent on a disposable lab VM.

### GOAL

Verify that Witch Dog detects a real synthetic vulnerability.

### INPUT

- [Issue #10](https://github.com/gabalmighty/witchdog/issues/10)
- Guide: docs/vapt-execution.md
- Tool: tools/vapt.py

### STEPS

1. Provision an isolated synthetic application.
2. Record the VM image, target, network and tool versions.
3. Confirm that unapproved egress is blocked.
4. Create and approve a private test engagement.
5. Run preflight, plan, precheck and ZAP through Witch Dog.
6. Validate a deliberately vulnerable fixture and clean control.
7. Check scanner warnings and failure states.
8. Verify all report hashes and cleanup evidence.
9. Submit test receipts and a reviewed PR.

### GATES

Do not test production or real employee records.

Do not bypass ZAP precheck.

Do not call a scanner alert a confirmed exploit without verification.

### OUTPUT

Reproducible lab proof, false-positive data and regression fixtures.

## Issue #14 — PR reviewer acceptance

**Priority:** P1. **Owner:** Coding agent with a human reviewer.

### GOAL

Qualify the GitHub Action and local OpenCode reviewer.

### INPUT

- [Issue #14](https://github.com/gabalmighty/witchdog/issues/14)
- Guide: docs/pr-review.md
- Tool: tools/pr_review.py

### STEPS

1. Create a disposable public test repository.
2. Pin Witch Dog to an approved commit.
3. Add fake secret and unsafe workflow test changes.
4. Run a deterministic review without AI.
5. Run an approved free model and record availability.
6. Test a provider key with safe synthetic code.
7. Verify bot comment updates and stale PR rejection.
8. Repeat the review on Windows and Linux.
9. Compare findings with an independent human review.

### GATES

Do not expose credentials to OpenCode or a PR.

Do not enable secret-bearing jobs on fork PRs.

Do not run build scripts from the PR in the review job.

### OUTPUT

Acceptance matrix, actual model costs and review-quality scores.

## Issue #27 — Advisory and asset correlation

**Priority:** P1 after #21 and #25.

### GOAL

Match verified dependency identifiers to relevant CVEs.

### STEPS

1. Use only local scanner and intelligence JSON.
2. Match exact CVE IDs before any heuristic product match.
3. Require a reviewed map for package-name aliases.
4. Keep findings at POTENTIAL until preconditions are verified.
5. Include KEV dates and affected component evidence.
6. Test a match, near miss and no match.

### GATES

No web access or remote scans from this matcher.

A feed match is not a proven runtime vulnerability.

### OUTPUT

Offline matcher, tests and bounded private reports.
