# Operations: local runs, scheduled intelligence, and safe updates

## Local workstation / application VM

Clone alongside target repos, then run the universal prompt in the README. To avoid AI provider dependencies, run:

- Linux/macOS: `python3 tools/witchdog.py scan --root .. --output .witchdog/runs`
- Windows PowerShell: `py -3 tools/witchdog.py scan --root .. --output .witchdog/runs`

Explicitly pass `--root`; output is local, normally `.witchdog/runs/`. No repo editing or remote scanning occurs in the Python scanner. Protect output and avoid publishing it in a public issue/PR.

## Scheduling

- **Security intelligence:** GitHub workflow `intelligence.yml`, twice per day, deterministic ingest into a reviewed PR. Needs Actions enabled and repository Settings → Actions → General allowing Actions to create PRs (if GitHub token settings require it). Workflow never auto-merges.
- **Local application audit:** schedule a pinned, trusted Witch Dog version with a low-privilege user using Windows Task Scheduler or systemd timers/cron. Use `python ... scan` for unattended runs; do not run OpenCode headless with broad filesystem/shell permissions on production.
- **Updating instructions:** use a reviewed immutable release tag / checked commit; `git pull` alone on a privileged production task is a supply-chain risk. Fetch/review in a separate directory, verify signature/hash and then promote. Pin executable code, not necessarily intel data.
- **On-call:** treat urgent advisories as event-triggered, not next-midnight-only. Missing feeds or unauthorized collector access should alert, not mark assets safe.

## GitHub workflow safety

Scheduled workflows run on the default branch, may be delayed, and public-repo schedules may be disabled after 60 days inactivity. GitHub-hosted runners for public repositories are usually free, but are subject to usage limits/policy. Keep source feeds allowlisted, response size limited and outputs normalized.

Never combine untrusted PR checkout, a powerful GitHub write token and an agent allowed to run shell commands. AI-generated changes must be treated as proposals and independently verified. Prefer a separate, read-only AI research workflow with artifact-only output until a security review approves the PR promotion flow.

## Suggested rollout tests

1. One developer Windows laptop auditing two synthetic repos (including a deliberately tracked fake `.env` file).
2. One Linux VM without Docker/Kubernetes credentials; verify that runtime checks show `UNKNOWN`.
3. Multi-repo Git checkout with a nested submodule, malformed package.json and symlinks; no traversal or crash.
4. Unavailable RSS or malformed KEV input: workflow fails and preserves last known-good data.
5. Public PR review: inspect that no private path, hostname, .env value or customer address appears.
6. Simulated advisories for Vite and NGINX: verify source-only vs live verdict separation.

## Public CISA KEV feed resilience

If the official cisa.gov JSON endpoint returns HTTP 403 or another transport error, the collector retries using [CISA's official `cisagov/kev-data` mirror](https://github.com/cisagov/kev-data) (develop branch). Both URLs are exact-allowlisted. An invalid JSON/schema fails the run; no arbitrary redirect or third-party proxy is trusted. The system does not update the maintained intelligence snapshot on a failed run.
