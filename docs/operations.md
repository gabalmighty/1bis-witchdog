# Witch Dog operations

## Local scans

Clone Witch Dog beside the target repositories.

Linux:

    python3 tools/witchdog.py scan --root .. --output .witchdog/runs

Windows:

    py -3 tools/witchdog.py scan --root .. --output .witchdog/runs

Run as an unprivileged user. Keep the scan output in private storage.

The baseline scanner does not change source files or scan remote hosts.

Dockerfile F06 checks each declared base image. A pinned digest is only source evidence.

An E01 filename check is not a content or history secret scan. It must remain UNKNOWN until a trusted scanner verifies those surfaces.

## Intelligence schedule

The GitHub workflow uses two UTC cron events each day.

The planned times are 08:31 and 20:31 in Asia/Manila.

The workflow also accepts a manual trigger.

A push to main starts the feed pipeline when a tracked intelligence source changes.

The workflow proposes a data-only pull request. It does not merge the request.

See [intelligence operations](intelligence-operations.md) for the first-run check.

## Watch for missed runs

Use a separate CI machine to check the GitHub schedule.

    python3 tools/intel_health.py --max-age-hours 16

Configure the CI monitor to alert when the command returns code 2.

A missing scheduled run is a failure. Do not infer feed freshness from an old data file.

## Update Witch Dog

Use a reviewed release or exact commit on production hosts.

Do not run a privileged unattended task that pulls and executes new main code.

Download and test new code in a separate directory.

Move the reviewed version into the production job after approval.

## Protect CI

Do not combine a GitHub write token with untrusted PR execution.

Run source review, CI tests, and comment publication in separate stages.

Keep secrets away from the model worker.

Use read-only Git access for source inspection.

## CISA KEV fallback

The collector reads the official CISA feed first.

If the primary request fails, it can use CISA's public GitHub data mirror.

Both sources have exact allowed URLs.

An invalid feed holds the run. Witch Dog keeps the last known-good data file.

## Checks before rollout

- Test an offline VM and a Windows laptop.
- Test a folder with several Git repositories.
- Test invalid RSS and CISA JSON fixtures.
- Test missing access and stale evidence.
- Test the workflow on a public data-only change.
- Verify that no client data appears in the public repository.
