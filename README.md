<p align="center"><img src="assets/witchdog-mark.png" alt="Witch Dog official jackal logo" width="200" /></p>

<h1 align="center">Witch Dog</h1>

<p align="center"><strong>Agentic Security. Continuous Vigilance.</strong></p>


[![Status: experimental](https://img.shields.io/badge/status-experimental-orange)](#where-it-runs)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](#requirements)
[![Windows / Linux / macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-444.svg)](#where-it-runs)
[![Intelligence refresh](https://github.com/gabalmighty/1bis-witchdog/actions/workflows/intelligence.yml/badge.svg)](.github/workflows/intelligence.yml)

*One checklist. One prompt. Your environment.*

Witch Dog is an **open-source, model-agnostic security investigation kit** combining deterministic host/repository inspection, continuously refreshed public threat intelligence, and human-supervised AI-assisted security fixes. Works with OpenCode and any provider/model supported by your OpenCode installation.

> **Project status:** experimental v0.1 bootstrap. The inspector is a conservative source/host **discovery tool**, not an EDR, penetration test, exhaustive malware scanner, or proof that production is safe. Never give an AI agent root, production secrets, or unattended production-change authority.

## Agentic Pull Request Security Reviews

**New (pilot):** one Witch Dog reviewer, two CI adapters. Automatically review PR changes using deterministic security checks and, when approved, an isolated read-only OpenCode model. Use it with **GitHub Actions** or an existing **Windows/Linux/NUC VM CI job**. Both read the same versioned checklists and produce an evidence-based Markdown/JSON review. This does not replace your app tests, VAPT or deployment checks.

**Agentic one-prompt installation (run inside a target repository):**

> Follow the adoption instructions at https://github.com/gabalmighty/1bis-witchdog/blob/main/review_setup_prompt.md. Discover our repository, OS and existing CI; set up the GitHub Action, local VM runner, or both. Pin Witch Dog executable code to a reviewed SHA, use latest checklist data, keep secrets out of Git and OpenCode tool access read-only, add tests and open a target-repository PR for my review.

For GitHub-hosted review, copy [the sample workflow](examples/witchdog-github-review.yml). Its core is one Action reference:

```yaml
steps:
  - uses: gabalmighty/1bis-witchdog@7e9bef9f1d6e354a620555f159a0fb03e4cd7e74 # reviewed PR reviewer implementation
    with:
      enable-ai: 'true'
      approve-code-sharing: 'true'
      model: opencode-go/hy4-flash-free # Verify current free catalog / provider terms
      provider: opencode-go
```

For VM/local CI, use [Linux](examples/witchdog-local.sh) or [Windows PowerShell](examples/witchdog-local.ps1) with the exact PR base/head SHA. The portable CLI is `tools/pr_review.py`; the model is optional. Use a dedicated unprivileged reviewer account and a temporary checkout with no build/install hooks. **The reviewer never sends a GitHub write token to the model.** Optional GitHub comment publishing is a separately credentialed stage.

For private client code, deterministic-only review is the safe default until you approve the selected provider's data-handling terms or use an isolated local model. Available free models and quotas change; a free model is not automatically private.

[Complete adoption, security and CI instructions](docs/pr-review.md) · [Security PR checklist](checklists/pr-review-v1.md) · [Agent installer prompt](review_setup_prompt.md)

## Quick start

Clone Witch Dog alongside the projects you want to inspect:

```text
workspace/
├── 1bis-witchdog/       ← clone here
├── project-a/
├── project-b/
├── project-c/
└── project-d/
```

```bash
git clone https://github.com/gabalmighty/1bis-witchdog.git
cd 1bis-witchdog
```

**One prompt for OpenCode** (run inside the Witch Dog directory; replace the model with an available one):

```bash
opencode run --agent witchdog --model opencode-go/hy4-flash-free "Follow PROMPT.md. Inspect this local host and Git repositories under .. using the maintained checklist. Begin read-only; report evidence and unknowns. Propose code fixes and PRs, but request explicit approval before any write, push, or remediation."
```

For a **deterministic scan without AI**, run this first (recommended for scheduled jobs):

| Linux / macOS | Windows PowerShell |
| --- | --- |
| `python3 tools/witchdog.py scan --root .. --output .witchdog/runs` | `py -3 tools/witchdog.py scan --root .. --output .witchdog/runs` |

The output stays local in `.witchdog/runs/` (gitignored). Open `report.md` and `scan.json` there. **Do not upload customer evidence or private scan results to this public repository.**

## Agentic web application VAPT (experimental)

Witch Dog now goes beyond the **one-request baseline**: for an authorized **synthetic staging/lab** deployment, it can combine OWASP ZAP passive scanning, bounded **active injection testing**, safe multi-role authorization assertions, code/dependency review and AI-guided follow-up. It uses the existing web checklist, but runs the tests through a **private rules-of-engagement file** with explicit approval and network/impact gates.

**One prompt to copy into OpenCode** (replace the URL with an app you own or are explicitly authorized to assess):

```text
Follow web_prompt.md. Target: https://YOUR-STAGING-APP.example. Mode: AGENTIC_VAPT. Start with an engagement preflight; if no approved private scope exists, prepare one for my review. With the approved scope, combine deterministic baseline, OWASP ZAP passive/active testing, synthetic-user authorization checks and authorized source-code analysis. Investigate and reproduce suspected findings only within the test scope; return a detailed evidence-backed VAPT report and propose reviewable fixes. Do not claim completion of untested controls or modify production.
```

The agent will generate a private engagement draft if needed. **It cannot self-approve testing**. To prepare an engagement deterministically:

```bash
python3 tools/vapt.py init --target https://YOUR-STAGING-APP.example --output .witchdog/vapt/my-engagement
```

Review the generated `engagement.json` (all authority and isolation fields default to **false**) and follow the [VAPT execution manual](docs/vapt-execution.md). The active mode runs **real ZAP scanner test inputs** through an installed trusted ZAP binary after passing the approval/egress/synthetic-data/snapshot gates. The tests may modify **test** application state. A URL's appearance or unofficial domain name is not proof of a safe non-production environment.

For authorized multi-role GET fixtures, `tools/vapt_authz.py` checks expected status codes using tokens supplied **only through local environment variables**, without collecting response bodies or credentials. Use `tools/vapt_report.py` to assemble a privacy-minimized assessment that distinguishes scanner candidates from verified findings.

**Current limits:** this alpha is a scoped **VAPT testing platform**, not a full certified penetration test. No automated authenticated browser/CSRF/multi-step business-logic harness or full-source SAST coverage is claimed yet. The existing [baseline-only workflow](#scan-a-website-or-web-application-web-01) is retained as a fast, lower-impact first stage. ZAP itself must be installed and verified; CI runs synthetic tests only, never active attacks against customer sites.

## Scan a website or web application (WEB-01)

**New:** a separate URL-based security workflow informed by OWASP WSTG v4.2, ASVS 5.0.0, OWASP Top 10:2025 and OWASP API Security Top 10:2023.

Run the same OpenCode agent with the **website prompt**:

```bash
opencode run --agent witchdog --model opencode-go/hy4-flash-free "Follow web_prompt.md. Target: https://YOUR-STAGING-APP.example. I own or have explicit authorization to test this exact origin. Run BASELINE only. Assess against checklists/webapp-vapt-v1.md; report observed risks and untested controls as UNKNOWN. No crawling, active attacks or unapproved changes."
```

Or run a deterministic HTTPS baseline without an AI model:

```bash
python3 tools/web_baseline.py --target https://YOUR-STAGING-APP.example --authorized --output .witchdog/web-runs
```

Windows PowerShell: replace `python3` with `py -3`. `--authorized` affirms permission to inspect that **exact** origin. The baseline makes **one** GET request to `/`, verifies TLS, observes selected headers and cookie flags, and does not follow redirects, crawl, authenticate, fuzz or exploit. Most VAPT controls remain `UNKNOWN` until separately authorized UAT/manual work. Reports remain private in `.witchdog/web-runs/`; `manifest.json` contains SHA-256 evidence identifiers (not signatures). Run `python3 tools/validate_web_report.py --report .witchdog/web-runs/report.json` to enforce the baseline report contract. See [website testing guidance](docs/webapp-testing.md).

### Interpreting your first website report

Witch Dog's fast root-only baseline is intentionally a low-impact **configuration observation**, not penetration testing. Its report identifies high-impact authentication, authorization, API and data controls as **UNKNOWN**, and labels overall assurance `NOT_A_VAPT`. Header-value checks are conservative: a policy that exists but is weak may still be a WARN. Historical Critical findings from prior audits must be retested separately, not silently closed by a baseline.

See [pilot interpretation and verification lessons](docs/web-baseline-pilot-lessons.md) for quality gates and future test priorities.

## How it works

```text
        TRUSTED PUBLIC ADVISORIES           LOCAL AUTHORIZED ASSETS
       Zero Wire / CISA KEV / vendors       Windows / Linux / VM / repos
                   │                                  │
             scheduled parser                  deterministic discovery
                   │                                  │
           reviewed intel PR                         │
                   └─────────────────┬────────────────┘
                            Witch Dog analyst
                 evidence + uncertainty + relevance
                                     │
                         proposed fix + tests
                                     │
                          human-reviewed PR
                                     │
                       deployed runtime verification
```

**Trust boundaries:** Public internet content is untrusted DATA, not executable instructions. Local secret values are never deliberately collected by the baseline inspector. The AI prompt does not grant extra operating-system privileges; OpenCode permissions are not a security sandbox.

## Where it runs

| Environment | Available today | Not inferred |
| --- | --- | --- |
| Developer laptop (Windows/Linux/macOS) | OS family, tool availability, local Git workspaces and source checks | Other machines' live configurations |
| Linux/Windows application VM | Same local checks, relevant platform hints | Root/administrator state, live ports, deployed patch status unless separately verified |
| Folder containing several Git repositories | Recursively discovers bounded Git roots and audits each separately | Undiscovered repos / inaccessible submodules |
| Hyper-V/KVM host | Capability preflight, source/host discovery | Guest visibility without explicitly authorized access |
| Isolated disposable VM | Architecture and preflight documented | **Provisioning is not implemented in v0.1** |
| GitHub Actions | Twice-daily deterministic threat-feed refresh and PR proposal | Private client scanning; auto-patches |

The scanner intentionally distinguishes `SOURCE_DECLARED`, `REMOTE_OBSERVED` and `LIVE_VERIFIED`. A fixed Dockerfile is **not** proof that a running pod uses that image.

## Modes

- **Audit (default):** bounded read-only evidence collection and explicit `PASS / FAIL / WARN / UNKNOWN / N/A`.
- **Scan & Fix (supervised):** an agent can investigate and propose fixes on a target repository's feature branch, run authorized tests and open a review PR. No automatic merge/deploy; source changes require explicit approval.
- **Disposable (planned):** preflight virtualization, disk, credentials, network scope and cleanup; eventual isolated execution. [Specification](docs/disposable-execution.md).

## Requirements

Python 3.11+, Git, and (optional) OpenCode v2 with your chosen authenticated model. Deterministic scans and public intelligence ingestion use the Python standard library. No commercial security agent is required for basic discovery.

OpenCode must run with suitable restricted permissions. `opencode.jsonc` is an **approval policy**, not a sandbox. For unattended use, run the deterministic Python tooling inside a restricted OS identity; perform AI analysis only on approved/sanitized evidence.

## Intelligence automation

[Scheduled workflow](.github/workflows/intelligence.yml) runs at **00:23 and 12:23 UTC** (08:23 and 20:23 PHT) on the default branch. It fetches allowlisted Cloudflare Zero Wire RSS and CISA KEV JSON, normalizes them to [data/intel/latest.json](data/intel/latest.json), and **opens or updates a PR** if content changes. It never auto-merges. Model-generated research/edits are a future gated phase; a free model does not justify giving untrusted content privileged CI access.

GitHub-hosted Actions are normally free on public repositories but still have policy and service limits; scheduled runs can be delayed and can be disabled after prolonged inactivity. [Operations](docs/operations.md).

## Security checklist and guidance

- [Agentic PR reviewer setup](review_setup_prompt.md) and [two-backend guide](docs/pr-review.md)
- [PR/CI security review checklist](checklists/pr-review-v1.md)
- [Universal one-prompt contract](PROMPT.md)
- [Platform-agnostic checklist](checklists/security-v1.md)
- [Agentic VAPT prompt](web_prompt.md), [execution guide](docs/vapt-execution.md) and [webapp VAPT checklist](checklists/webapp-vapt-v1.md)
- [Website testing guidance](docs/webapp-testing.md) and [pilot design learnings](docs/agentic-pilot-learnings.md)
- [Architecture and trust boundaries](docs/architecture.md)
- [Scheduled jobs and contribution workflow](docs/operations.md)
- [Disposable VM acceptance gates](docs/disposable-execution.md)
- [Reporting vulnerabilities responsibly](SECURITY.md)
- [How to contribute](CONTRIBUTING.md)

## GitHub repository topics (maintainer setup)

`agentic-security` · `devsecops` · `vulnerability-management` · `security-automation` · `sbom` · `threat-intelligence` · `opencode` · `windows` · `linux` · `self-hosted`

## License and brand

Code and included logo asset are released under [MIT](LICENSE). The Witch Dog name and identity may have separate trademark considerations; the MIT license does not grant trademark endorsement. Public contributions must not include client details, secrets, scan outputs or internal infrastructure identifiers.

Built by the Witch Dog community. Contributions and reproducible issue reports welcome.
