# Witch Dog — Developer Security Scan

Copy this prompt into your approved coding agent.

Use it on a laptop, workstation, VM, or build host that you control.

## Ready prompt

```text
GOAL
Run a read-only Witch Dog security audit on this computer and its approved local Git repositories. Check for developer malware, unsafe startup scripts, suspicious Git changes, exposed secrets, and vulnerable dependencies. Distinguish observed facts from unknowns.

INPUT
Use https://github.com/gabalmighty/witchdog and read AGENTS.md, PROMPT.md, and checklists/developer-malware-v1.md. Use a reviewed Witch Dog commit. Identify the host OS and authorized workspace path first.

SCOPE
Local read-only inspection only. Inspect the current user home for known loader artifact filenames. Inspect approved local Git worktrees and the Git index. Never fetch, pull, build, install, run project scripts, or contact suspect domains. Do not scan remote hosts or third-party repositories without separate authority.

STEPS
1. Detect Windows, Linux, or macOS and confirm the host or VM being inspected.
2. Confirm that the Witch Dog checkout is trusted and separate from suspect source.
3. Run Witch Dog's deterministic local scan with the approved workspace root.
4. Review developer malware controls M01–M09 and normal security controls.
5. Review source and Git evidence. Never execute code from the target.
6. Check the published malicious-package catalog and relevant local lockfiles.
7. Keep secret contents, full process command lines, and private host data out of LLM prompts.
8. Mark remote Git refs, running processes, scheduled tasks, persistence, and exposed credentials UNKNOWN unless separately inspected.
9. If evidence suggests active compromise, STOP routine work and escalate to incident response.
10. Propose safe next actions. Do not implement or merge remediation.

GATES
No auto-remediation, credential rotation, history rewrite, firewall change, or process termination.
No git pull, npm install, npm run, editor auto-tasks, or unapproved network requests in a suspect repository.
A lack of local findings does not mean the host or its remote branches are safe.
If the device is actively compromised, use a trusted isolated responder machine.

OUTPUT
Give the scope, OS, tool version, and exact checks completed.
List each finding with control ID, risk, evidence path and confidence.
Separate observed, suspected, deferred and unknown results.
Store detailed reports privately. Summarize urgent containment and credential rotation needs.
```

## Direct scanner commands

Use a trusted Witch Dog checkout. Do not run commands from suspect repositories.

Windows:

```powershell
py -3 tools/witchdog.py scan --root .. --output .witchdog/runs
```

Linux or macOS:

```bash
python3 tools/witchdog.py scan --root .. --output .witchdog/runs
```

The root is an approved workspace folder, not a drive root.

The scanner does not need an API key. OpenCode is optional.

The scanner does not execute target code or connect to the Internet.

## If a security incident is active

Do not treat Witch Dog as a replacement for incident response.

Arrange device isolation, forensic collection, and credential revocation through your security team.

Use a separate trusted device for account recovery and key rotation.

Do not trust a clean worktree as proof that remote Git branches are clean.

Do not assume a terminated loader means that persistence is gone.

See [developer incident response](docs/developer-incident-response.md).

## Read more

- [Malware controls](checklists/developer-malware-v1.md)
- [Developer threat research](docs/developer-threat-research.md)
- [Normal host audit prompt](PROMPT.md)
- [Witch Dog security policy](SECURITY.md)
