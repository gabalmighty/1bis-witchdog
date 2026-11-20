# Intelligence schedule and recovery

## Verified state — November 20, 2026

Witch Dog collects public intelligence through GitHub Actions.

The default branch is `main`. The data file is `data/intel/latest.json`.

The first feed run failed because the Cloudflare feed path had changed.

PR #18 fixed the feed URL. The next push-triggered collector passed.

GitHub then blocked the bot from opening a data PR.

A maintainer recovered the first data update through PR #19.

### Manual workflow verification

The owner enabled GitHub Actions pull request creation.

[Manual run #44675875203](https://github.com/gabalmighty/witchdog/actions/runs/44675875203) completed successfully.

- Trigger: `workflow_dispatch` on `main`.
- Started: 2026-11-20 04:39 UTC (12:39 Asia/Manila).
- Collection, parser tests, and schema checks: **PASS**.
- Artifact upload and download: **PASS**.
- Data proposal job: **PASS**.
- Data result: **No intelligence changes**.
- Snapshot: **88 advisories** from **2 sources**.

The workflow did not create a new PR because the current data matched `main`.

It removed the old `bot/public-intel-refresh` branch. This was expected.

**Result:** The manual collection and proposal pipeline works.

No `schedule` event has run yet. The manual result does not prove cron delivery.

### What updates automatically

The workflow can propose changes to **`data/intel/latest.json` only**.

It creates a review PR when normalized advisory data changes.

It does not update this runbook or merge data without review.

Use GitHub Actions for live run status. Update this document when the workflow design changes.

## Full CISA KEV coverage

The first snapshot retained only the latest 75 CISA entries.

The updated collector preserves all official KEV records within its bounded catalog limit.

Each record includes the CVE ID, vendor, product, date added and due date.

The validator rejects duplicate IDs, invalid source URLs and excessive catalog size.

A catalog above the safety limit causes a HOLD. The tool does not silently truncate entries.

A fresh feed can create a larger data-only review PR. Check its schema and source before merging.

The published catalog is still advisory data. It does not prove that a scanned asset is affected.

## Full-catalog deployment verification

[PR #28](https://github.com/gabalmighty/witchdog/pull/28) removed the 75-item CISA KEV limit.

[Run #44729590165](https://github.com/gabalmighty/witchdog/actions/runs/44729590165) fetched and validated the complete catalog.

GitHub Actions created [data PR #29](https://github.com/gabalmighty/witchdog/pull/29) without a maintainer workaround.

The validated data contains **1,786 KEV entries** and **13 Zero Wire entries**.

The data-only PR was reviewed and merged. All 88 prior entries remain in the catalog.

This verifies the live feed and bot PR path. Cron delivery and an independent host alert remain unverified.

## Schedule

| UTC | Asia/Manila |
|---|---|
| 00:31 | 08:31 |
| 12:31 | 20:31 |

GitHub can delay or drop a scheduled event.

The workflow also has a manual trigger.

A push to main starts the feed job when its source files change.

The manual run passed. The next scheduled run is still an open acceptance check.

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
