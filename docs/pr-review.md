# Witch Dog — Agentic PR Review for GitHub Actions and Local CI

Witch Dog has two review adapters. One is a GitHub Action. The other is a Python CLI for local CI hosts. Both use the same security rules. This is a PR change review, not a full VAPT or runtime audit.

## 1. Fastest GitHub adoption

Inside the target repository create .github/workflows/witchdog-review.yml using the sample at examples/witchdog-github-review.yml. It contains a single reusable Action reference:

    uses: gabalmighty/1bis-witchdog@7e9bef9f1d6e354a620555f159a0fb03e4cd7e74

The sample pins a reviewed 40-character commit SHA. Keep executable code pinned to an approved Witch Dog release/commit; update that pin only through a reviewed PR. Newer checklist data can continue to refresh from the latest audited main revision without updating scripts.

Recommended workflow trigger: pull_request on opened, synchronize, reopened and ready_for_review; permissions contents: read and pull-requests: write; job restricted to PRs created from branches in the same repository. Do not use pull_request_target with untrusted PR checkout. Fork PRs are intentionally not covered by this secret-bearing example; use a separate manual review or a fork-safe secretless workflow.

For public code, and with accepted provider data terms, set enable-ai: 'true' and approve-code-sharing: 'true'. Choose a currently available free model with opencode models. No provider API key is required when that model is available without authentication. The model in the sample is only a starting selection: free catalogs and quotas change. If the model requires a key, create WITCHDOG_PROVIDER_KEY under repository Settings > Secrets and variables > Actions and pass it via the Action input. Never commit secrets to workflow YAML.

For private or sensitive client code, default to deterministic-only review (enable-ai: 'false'). Enable AI only after approval of the provider/model retention and geography; consider a client-hosted model. The Action never prints the API key and never sends the GitHub write token to OpenCode.

GitHub-hosted Actions are generally free for public repositories within service limits; private repositories have included monthly usage and can incur costs. GitHub self-hosted runner usage is free but consumes your own hardware. The independent local CLI below avoids hosted Actions entirely.

## 2. Local VM/NUC reviewer: same engine

Prerequisites: Python 3.11+, Git CLI, a trusted pinned Witch Dog checkout and a temporary restricted Git checkout of the target PR SHA. OpenCode v2 CLI is optional.

The CI orchestrator must fetch base and head SHAs and check out exact HEAD. Do not run npm install, dotnet build, Git hooks, postinstall scripts or arbitrary target code in the secret-bearing reviewer account. Run product tests in a separate sandboxed build job. Use a dedicated OS identity without root, production SSH credentials or Docker socket access.

### CLI

    python3 /path/witchdog/tools/pr_policy.py --out /private/job/policy --bundled /path/witchdog --ref main
    python3 /path/witchdog/tools/pr_review.py inspect --repo /private/job/target --base BASE_40_HEX_SHA --head HEAD_40_HEX_SHA --out /private/job/review --kit /private/job/policy
    python3 /path/witchdog/tools/pr_review.py validate --out /private/job/review

For an approved model/provider:

    python3 /path/witchdog/tools/pr_review.py ai --out /private/job/review --model opencode-go/hy4-flash-free --provider opencode-go --allow-code-to-model

Supply optional provider credentials via process environment WITCHDOG_PROVIDER_KEY sourced from OS secret storage, never from a prompt or checked-in file. The key is mapped to the provider variable inside the OpenCode process. GitHub write credentials are not passed to the AI process.

The convenience scripts examples/witchdog-local.sh and examples/witchdog-local.ps1 use environment variables for model, mode, paths and output. They do not install background services or schedule tasks. Your existing CI/cron runner can invoke them.

For optional PR comment publication, use a separate narrowly credentialed process invoking tools/pr_publish.py with GITHUB_TOKEN, repository, PR number, expected HEAD SHA and report directory. It checks PR state/HEAD and updates only the Actions bot's own marked comment. Local PAT-based publication may create a new comment instead of updating one, because the updater deliberately avoids editing other users' comments.

## 3. Execution architecture

    GitHub PR event OR local CI poll
               |
        Exact base/head commit
               |
        Trusted Witch Dog CLI
               |
      Bounded Git diff and patterns
               |
        Versioned checklist DATA
               |
         Sanitized context packet
               |
      Optional read-only OpenCode
         (no shell/edit/web tools)
               |
      Deterministic + AI suggestions
               |
           Private report
               |
      Separate PR comment publisher

The reviewer never executes PR code. The model runs in a separate temporary folder with a deny-all OpenCode permissions policy. Untrusted PR comments and source data cannot grant tools. Provider models receive bounded sanitized diff context only after explicit approval. Regex redaction is imperfect: do not share sensitive client code with an unapproved online model.

## 4. Keep checklists current without unreviewed code execution

tools/pr_policy.py fetches approved Markdown files from Witch Dog. It resolves main to a commit and records file hashes. It does not download code or change permissions. A failed fetch uses bundled rules and marks them as stale. Pin the Action to a reviewed commit.

Policy Markdown is reference data, not an instruction source that can override the shipped tool policy.

## 5. Report meanings

- REVIEWED means the bounded diff was inspected; it never means the PR or deployment is safe.
- PARTIAL indicates truncated diff context, stale policy or unavailable AI model when requested. The report remains visible, not a false PASS.
- Deterministic matches are candidates, not exploited vulnerabilities; coding agents still need safe verification and human review.
- Source review cannot establish deployed runtime reachability, patch identity or completed VAPT.
- The reviewer never edits target code, auto-merges, rotates credentials or deploys.

## 6. First-project acceptance

1. Make a synthetic same-repository PR with a broad dev server bind, unsafe CI trigger and fake test secret.
2. Confirm file/new-line findings without secret values.
3. Add PR prompt-injection text; confirm no shell/edit/network tools and no GitHub token in the model process.
4. Run with AI disabled, then with an approved available model. A provider failure should produce PARTIAL, not a clearance.
5. Push another commit: the bot updates its own comment and stale HEAD publication is rejected.
6. Confirm fork PR gating and no secret exposure.
7. Run the same CLI on Windows and Linux local CI, compare results.
8. Keep normal deterministic product CI, SAST, VAPT and deployment checks separate.

## Reference and caveat

The external Marketplace action inspired the PR comment design. Witch Dog uses separate code for permissions and local CI. Read the official GitHub and OpenCode security guides. OpenCode permissions are not an OS sandbox. Use isolated VMs for private clients.

## Cross-service identity and authorization extensions

The reviewer reads the identity authorization checklist as data. Check account creation, role changes, password resets and file access. Check raw query objects and token transfers. Look for generic routes that bypass protected operations. Record UNKNOWN when the change lacks context. Do not publish private findings.
