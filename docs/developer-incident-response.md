# Developer Security Incident Response

Use this guide if Witch Dog finds a credible malware or credential-theft indicator.

A detection is not a full forensic investigation.

## 1. Stop unsafe work

Do not run commands from a suspect project.

Avoid npm install, npm run, build, lint and editor auto-tasks.

Do not pull or merge a branch that has not been checked.

Do not run a coding agent with production keys on a suspected infected device.

Do not download or execute code from a suspect server.

## 2. Notify and contain

Tell the designated security responder.

Coordinate network isolation with the device owner.

Avoid routine cleanup before collecting required incident evidence.

Record the device, time, affected accounts, and who approved each action.

Use the organization's approved incident response and legal process.

## 3. Preserve evidence

Keep a private copy of the relevant alerts, timestamps and Git refs.

Record file hashes and process ancestry when approved tools permit it.

Do not copy raw secrets or malware samples into public issues.

Keep chain-of-custody notes with the incident.

Do not assume an absent file means a past payload never ran.

## 4. Restrict exposed credentials

Use a separate trusted device to revoke affected sessions and tokens.

Review GitHub tokens, SSH keys and package publishing access.

Review cloud, CI, registry, AI-provider and local developer credentials.

Rotate only with the service owner and its recovery plan.

Confirm that the old credentials no longer work.

## 5. Check source and runtime

Compare suspicious commits with an independently trusted source.

Inspect all relevant Git refs and pull request history with approved tools.

Check editor tasks, hooks, dependency scripts and local startup entries.

Use endpoint protection and forensic tools to inspect running processes.

A clean Git worktree does not prove clean remote branches.

A terminated process does not prove that persistence is removed.

## 6. Recover with approval

Restore from a verified clean image or snapshot when appropriate.

Use new credentials after the trusted device is restored.

Review the repository, build outputs, CI runners and deployed artifacts.

Preserve needed evidence before a destructive history rewrite.

Check the restored machine and repository again.

Do not mark a device CLEAN based only on Witch Dog's filename scan.

## 7. Close the incident

Record the root cause or mark it UNKNOWN.

Record each exposed account, rotated credential and affected asset.

Keep unresolved persistence and second-stage behavior OPEN.

Record the tests that prove each completed remediation.

Approve a return to normal development only after independent review.

## Sources

- [Microsoft Defender incident response](https://learn.microsoft.com/en-us/defender-xdr/plan-incident-response)
- [Microsoft Defender device isolation](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- [GitGuardian developer malware findings](https://blog.gitguardian.com/ghostaction-x-polinrider/)
