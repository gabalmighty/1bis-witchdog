# Developer Loader Threat Research — November 2026

## Purpose

This document records public threat research and reusable defensive checks.

Two private incident reports informed the test design.

The public repository does not include account names, private repo lists, credentials, or unpublished network indicators.

## Publicly confirmed techniques

Sonatype reported 12 malicious releases across 10 npm packages on November 4, 2026.

The loaders use Ethereum transactions to find a payload server.

They download and execute code after an affected runtime entrypoint loads.

Disabling npm install scripts alone does not prevent this runtime execution.

GitGuardian reported stolen-token reuse and unauthorized Git pushes in October 2026.

It also documented hidden VS Code tasks that launch JavaScript disguised as font files.

Some related variants create persistence that can remain after repository cleanup.

Witch Dog records these as public research, not proof about any specific developer.

## Local incident lessons

The private reports describe different observations.

One report found tampered Git commits and compromised repository content.

Another report found an active Node.js loader and hidden PowerShell process.

The second report did not identify the process relaunch mechanism.

A clean local checkout does not prove that a remote branch is clean.

A removed loader file does not prove that another persistence path is absent.

Commit timezone metadata alone does not prove the attacker's physical location.

The presence of a Git blob does not prove that a branch currently references it.

## Detection strategy

Use known behavior and package versions before IP-only indicators.

A command-and-control address can change during an incident.

Combine startup-script, hidden-task and file-type evidence.

Use the published exact npm release list for offline lockfile checks.

A lockfile match proves only that a version was declared in a local file.

Review whether a vulnerable package was installed and executed separately.

Preserve host, source and remote evidence as different classes.

Do not copy raw incident payloads into a public rule file.

## Current scan coverage

Witch Dog checks selected local files, npm lockfiles and known home artifact names.

It does not inspect running process trees or unknown persistence.

It does not fetch Git remotes or inspect all Git history.

No findings is not a malware-free verdict.

## Independent incident response

If the agent finds a credible loader path, stop ordinary development.

The security team must decide when to isolate and collect forensic evidence.

Rotate exposed credentials from a separate trusted device.

Review repository access and trusted branch history before development resumes.

Avoid using an automated cleanup script on an unresolved incident.

## Public references

- Sonatype, November 4, 2026: https://www.sonatype.com/blog/polinrider-loader-reappears-in-hijacked-npm-packages
- GitGuardian, October 27, 2026: https://blog.gitguardian.com/ghostaction-x-polinrider/
- OWASP npm guidance: https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html
- VS Code Workspace Trust: https://code.visualstudio.com/docs/editing/workspaces/workspace-trust

These sources may change. Verify their current details before closing an incident.
