# Witch Dog PR review setup prompt

Use this prompt in the TARGET project. Do not change Witch Dog during adoption.

## GOAL

Install a security PR reviewer with GitHub Actions, a local CI machine, or both.

Create a review pull request in the target project.

## INPUT

- Witch Dog source: https://github.com/gabalmighty/witchdog
- Installation guide: docs/pr-review.md
- PR policy: checklists/pr-review-v1.md
- Security policy: checklists/security-v1.md
- Identity policy: checklists/identity-authorization-v1.md
- Execution mode: Detect from the target project.

## SCOPE

Review only the approved target repository and CI configuration.

Use a separate folder for the Witch Dog checkout.

Keep executable Witch Dog code pinned to a reviewed commit.

Fetch newer checklists only as data. Do not execute them.

## STEPS

1. Detect the OS, Git remote, and active CI tools.
2. Check GitHub repository access and runner permissions.
3. Read the reviewed Witch Dog installation guide.
4. Select GitHub Actions, local CI, or both.
5. Set read-only Git access for the review stage.
6. Add the deterministic PR reviewer.
7. Select an available OpenCode model if approved.
8. Keep API keys in a secret store.
9. Deny shell, edit, and network tools in the model worker.
10. Keep GitHub write credentials out of the model process.
11. Add safe workflow or script triggers.
12. Test a fake secret and an unsafe CI configuration.
13. Test a stale PR and a fork PR.
14. Record the checklist commit and code revision.
15. Create a pull request with test evidence.

Use the examples in the Witch Dog repository.

## GATES

Do not execute PR build scripts in the credential-bearing reviewer stage.

Do not use pull_request_target with an untrusted checkout.

Do not send private code to a model without data-processing approval.

Do not claim that a free model is available until you check it.

Do not update executable code from an unreviewed branch.

Do not merge, deploy, or auto-fix source without separate authority.

## OUTPUT

Give the selected CI method and the files changed.

Name the reviewed Witch Dog commit and model.

Describe the secrets required and how to configure them.

Report passed tests, skipped checks, and remaining risks.

Open a review pull request. Do not merge it.
