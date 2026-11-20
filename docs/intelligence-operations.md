# Intelligence schedule and recovery

## Current state

The repository is public. The default branch is main.

The intelligence workflow has a valid schedule and a manual trigger.

As of November 20, 2026, GitHub reports no schedule runs for this workflow.

GitHub reports many successful quality runs. These runs do not prove that the intelligence job works.

The repository is new. The 60-day inactivity limit does not explain the missing run.

The exact cause is not confirmed. The available GitHub connection cannot read the workflow's enabled state.

## First push-run result

On November 20, the new push trigger started the intelligence workflow.

The parser tests passed. Feed collection then returned a ValueError.

Cloudflare's current Open feed link uses https://radar.cloudflare.com/zero-wire/feed.

Witch Dog previously used the older security RSS path.

The collector now uses the current URL and keeps the old path as a fallback.

The source handler rejects redirects and reports a safe source error code.

The next live run must confirm this fix.

## Schedule

Witch Dog now uses these times:

| UTC | Asia/Manila |
|---|---|
| 00:31 | 08:31 |
| 12:31 | 20:31 |

GitHub can delay or drop a scheduled event during high load.

A new push trigger runs the intelligence workflow when its source files change on main.

This trigger tests the feed pipeline after a reviewed source change. It does not prove that the cron event works.

## First run check

1. Open https://github.com/gabalmighty/witchdog/actions/workflows/intelligence.yml
2. Select Enable workflow if GitHub shows that control.
3. Select Run workflow.
4. Select the main branch.
5. Start the workflow.
6. Open the run summary.
7. Check both collection and proposal jobs.
8. If GitHub blocks pull request creation, check Actions settings.
9. Under Settings > Actions > General, allow Actions to create pull requests when permitted.
10. Review the data-only pull request.
11. Merge it after you verify its source and data.

A manual run proves only that the manual trigger works. Check the next scheduled event separately.

The collection job reads only approved public feeds. The proposal job can write only the normalized data file.

Do not give public feed text authority over scripts or prompts.

## External schedule check

Run this command on a separate DevOps machine.

    python3 tools/intel_health.py --max-age-hours 16

The script checks the public GitHub schedule run history.

It reports HOLD when no recent successful scheduled run exists.

Run the command with your normal cron or Task Scheduler service account.

Configure your existing monitoring system to alert on exit code 2.

This independent check can detect a missed GitHub schedule when GitHub does not start the workflow.

## Update policy

The workflow opens a pull request when normalized public data changes.

Main will not contain new data until a reviewer merges that pull request.

Witch Dog does not run scripts from an advisory. It treats feed text as untrusted data.

Review each new public source before you add it to the feed list.

## Known limits

- A passing data parser test does not confirm a live feed response.
- A manual GitHub Actions run does not confirm cron delivery.
- A GitHub Actions run can fail when it cannot create a pull request.
- A fresh advisory can arrive between two scheduled runs.
- A model summary cannot replace an official vendor advisory.

Use the original advisory before you make a patch decision.

## References

- GitHub scheduled events: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- GitHub workflow troubleshooting: https://docs.github.com/en/actions/how-tos/troubleshoot-workflows
