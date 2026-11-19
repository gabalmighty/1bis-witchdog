# Witch Dog portable Windows PR security reviewer.
# Run as unprivileged CI service account in an isolated PR checkout.
$ErrorActionPreference = "Stop"
if (-not $env:WITCHDOG_HOME -or -not $env:BASE_SHA -or -not $env:HEAD_SHA) {
  throw "Set WITCHDOG_HOME, BASE_SHA and HEAD_SHA."
}
$out = if ($env:WITCHDOG_OUTPUT) { $env:WITCHDOG_OUTPUT } else { Join-Path (Get-Location) ".witchdog/pr-review" }
$policy = Join-Path $out "policy"
$ref = if ($env:WITCHDOG_POLICY_REF) { $env:WITCHDOG_POLICY_REF } else { "main" }
python "$env:WITCHDOG_HOME/tools/pr_policy.py" --out $policy --bundled $env:WITCHDOG_HOME --ref $ref
if (-not (Test-Path (Join-Path $policy "checklists/pr-review-v1.md"))) { throw "No valid checklist" }
python "$env:WITCHDOG_HOME/tools/pr_review.py" inspect --repo (Get-Location).Path --base $env:BASE_SHA --head $env:HEAD_SHA --out $out --kit $policy
if ($LASTEXITCODE -ne 0) { throw "Deterministic reviewer incomplete" }
if ($env:WITCHDOG_ENABLE_AI -eq "true") {
  if ($env:WITCHDOG_APPROVE_CODE_SHARING -ne "true") { throw "Provider data policy not approved" }
  if (-not $env:WITCHDOG_MODEL) { throw "Select model" }
  $provider = if ($env:WITCHDOG_PROVIDER) { $env:WITCHDOG_PROVIDER } else { "opencode-go" }
  python "$env:WITCHDOG_HOME/tools/pr_review.py" ai --out $out --model $env:WITCHDOG_MODEL --provider $provider --allow-code-to-model
  if ($LASTEXITCODE -ne 0) { Write-Warning "OpenCode unavailable; deterministic findings retained" }
}
python "$env:WITCHDOG_HOME/tools/pr_review.py" validate --out $out
if ($LASTEXITCODE -ne 0) { throw "Report validation failed" }
Write-Host "Private report: $(Join-Path $out 'review.md')"
