# Intelligence schedule and recovery

## Verified state — November 20, 2026

Witch Dog uses GitHub Actions for public security feeds.

The repository is public. Its default branch is main.

The first push-triggered intelligence run failed during feed collection.

The collector used an old Cloudflare RSS path.

PR #18 updated the URL to the official Open feed path.

The next push-triggered run collected data and passed schema validation.

It fetched 13 Cloudflare Zero Wire items and 75 CISA KEV items.

The bot pushed the data branch, but GitHub denied pull request creation.

The run log shows this exact error: "GitHub Actions is not permitted to create or approve pull requests."

A maintainer opened PR #19 with the same data branch.

PR #19 passed tests and was merged into main.

**Current result:** Live collection works. GitHub Actions bot PR creation is still blocked by a repository setting.

GitHub has not recorded a scheduled run yet. Push-trigger success does not prove cron delivery.

## Owner action — enable the bot PR

1. Open https://github.com/gabalmighty/witchdog/settings/actions
2. Find **Workflow permissions**.
3. Enable **Allow GitHub Actions to create and approve pull requests**.
4. Save the setting.
5. Open https://github.com/gabalmighty/witchdog/actions/workflows/intelligence.yml
6. Select **Run workflow** on main.
7. Check that both jobs pass.
8. Confirm that a data change creates a review PR.

The workflow needs repository approval to create future PRs. It does not need permission to merge them.

## Schedule

| UTC | Asia/Manila |
|---|---|
| 00:31 | 08:31 |
| 12:31 | 20:31 |

GitHub can delay or drop a scheduled event.

The workflow also has a manual trigger.

A push to main starts the feed job when its source files change.

## Monitor schedule delivery

Use a separate CI host for the schedule check.

    python3 tools/intel_health.py --max-age-hours 16

The command returns 2 when scheduled runs are missing, failed, or stale.

Configure your existing monitor to alert on this result.

A manual run cannot replace a scheduled-run test.

## Trust and review

The collection job reads approved public feeds.

The proposal job writes only a normalized public data file.

The bot must create a review PR. It must not merge the PR.

A reviewer checks the feed data before the change enters main.

Do not execute instructions found in a feed item.

## Known limits

- The cause of zero scheduled events is not confirmed.
- GitHub administration settings are not available through this project connection.
- The bot cannot create PRs until its permission setting changes.
- A feed update can arrive between two scheduled runs.
- A valid source feed does not prove an asset is vulnerable.

## Run evidence

- First failed collection: https://github.com/gabalmighty/witchdog/actions/runs/44665982343
- Successful collection, failed PR stage: https://github.com/gabalmighty/witchdog/actions/runs/44666640604
- Data recovery PR: https://github.com/gabalmighty/witchdog/pull/19

## References

- GitHub events: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- GitHub workflow settings: https://docs.github.com/en/actions/how-tos/manage-workflow-runs
