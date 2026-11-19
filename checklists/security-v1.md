# Witch Dog: platform-agnostic security checklist v1

**Applies to:** repositories, Windows/Linux/macOS hosts, VMs, containers, private and public deployments **only where authorized**. The baseline script implements only a **subset**; unexecuted controls are UNKNOWN, never implicitly PASS.

**Every record includes:** control_id; authorized asset; observation level (`HOST_OBSERVED`, `SOURCE_DECLARED`, `LIVE_VERIFIED`); time UTC; scanner/tool version; evidence path or redacted reference; actual result (`PASS`/`FAIL`/`WARN`/`UNKNOWN`/`N/A`); confidence; limitations; approval/fix state.

**Run classes:** daily passive, deployment gate, weekly deep review, controlled UAT, incident only. No intrusive production tests without separate authorization.

## A. Inventory and actual exposure

| ID | Check | Required verification |
|---|---|---|
| A01 | Host/VM/container/cloud/DNS inventory and owner | Asset list, source, authorization |
| A02 | Active listeners, direct-origin paths, tunnels and exposed dev ports | Local network state and approved reachability checks |
| A03 | Running service = known commit/build/image/SBOM | Live artifact digest, not Dockerfile alone |
| A04 | OS/runtime/vendor package and web server module versions | Installed build and vendor backport channel |
| A05 | Unsupported software and unowned services | Lifecycle and owner |
| A06 | Debug/hot reload/development server not reachable in production | Runtime process AND reachability |
| A07 | Stale inventory, failed collectors, incomplete scans | Heartbeats and coverage errors |

## B. Vulnerability intelligence

| ID | Check | Required verification |
|---|---|---|
| B01 | Track authoritative vendor advisories, Zero Wire, CISA KEV, OSV/GHSA/EPSS | Source URL, publication/revision time |
| B02 | Map advisories to deployed and transitive packages | Lockfile/SBOM PLUS running artifact |
| B03 | Test vulnerability predicates (flag, module, protocol, exposure, user) | Evidence for each prerequisite |
| B04 | Verify distro vendor backports and patched build | Vendor package bulletin |
| B05 | Distinguish confirmed/potential/not-affected/unknown/verified-fixed | Evidence-class and reason |
| B06 | Reevaluate on changed advisory/KEV/EPSS/deployment | Event and prior state |
| B07 | Retest **running** patched binary/image after rollout | Live digest, version and feature flags |

### Additional controls from the November 2026 read-only agentic pilot

| ID | Check | Required verification |
|---|---|---|
| A08 | Distinguish declared, resolved, installed and **running** software instance identity | Graph, file, host and live digest separately |
| A09 | Reconcile Compose/K3s/CDN/Argo CD/CI topology and flag contradictions | Authorized deployment path; mark `CONFLICTING` |
| B08 | Inspect **each** direct/transitive resolved instance, including test runners | Per-instance dependency chain, role and affected range |
| B09 | Differentiate upstream NGINX, NGINX Ingress, distro/vendor builds and image tags | Product ID and actual binary provenance |
| B10 | Evaluate version, module, protocol, feature flags, listener and reachability as separate vulnerability predicates | Evidence matrix for each prerequisite |

## C. Host and persistence

| ID | Check | Required verification |
|---|---|---|
| C01 | Privileged users, NOPASSWD sudo, local administrators and capabilities | Redacted effective privileges |
| C02 | App process cannot elevate without separation | Real service account context |
| C03 | SSH keys, new UID0/admin accounts, timestomping and file integrity | Approved fingerprint baseline |
| C04 | Management SSH/RDP only through approved private channels | ACL and exposure |
| C05 | Cron, Task Scheduler, systemd, startup hooks, launch tasks | Approved baseline diff |
| C06 | OS package integrity, permissions, host sandboxing | Vendor verification |
| C07 | Collector cannot mutate prod, access Docker socket or secrets | Denied-capability tests |
| C08 | Tamper-evident logs, time sync and retention | Log receipts/clock status |

## D. Application authorization

| ID | Check | Required verification |
|---|---|---|
| D01 | Every sensitive route, callback, socket is authenticated | Auth matrix in UAT |
| D02 | Token actor/role resolved from current valid user | Negative synthetic identities |
| D03 | Revoked/unknown/disabled user and bad algorithms rejected | Safe reject tests |
| D04 | Cross-user/tenant/object protection, including counts and exports | Test-user access matrix |
| D05 | Optional auth/provisioning/mutation exceptions reviewed | Route middleware trace |
| D06 | Webhooks/callbacks authenticated and replay-proof | Synthetic controlled tests |
| D07 | Rate limiting, account lockout, secure temp credentials | Config and test |
| D08 | JWT/cookies/CSRF/CORS/session policy | Config and safe tests |
| D09 | XSS, SQL/command injection, untrusted uploads, CSV formula injection | Static & isolated tests |
| D10 | Machine credentials, least privilege, revocation | IAM and scopes |

## E. Secrets and privacy

| ID | Check | Required verification |
|---|---|---|
| E01 | Secrets in Git index, branch heads, history, dangling objects, CI artifacts | Redacted scanner results |
| E02 | Central secrets storage and rotation after exposure | Metadata, never values |
| E03 | Sensitive data in public assets, backups, HARs, DB dumps, exports | Authorized access checks |
| E04 | No anonymous access to protected personal/financial data | Synthetic bounded tests |
| E05 | Sensitive records encrypted, retention controlled | Key and ACL evidence |
| E06 | App cannot read cloud/AI/SSH/Kubernetes/admin keys | Mount and IAM review |
| E07 | AI prompts, logs, reports and Git PRs contain no secrets/PII | Redaction gate |
| E08 | SMB/share/backup exposure and permissions | Share policy evidence |

## F. Supply chain and automation

| ID | Check | Required verification |
|---|---|---|
| F01 | Lockfiles, branch protection, gitlinks/submodules and protected refs | Git policies and SHA alignment |
| F02 | Lifecycle scripts, IDE tasks, Git hooks and agent plugins | Executable paths reviewed |
| F03 | Obfuscation, payload carriers, malicious branch tips and hidden binaries | Hash and historical scan |
| F04 | CI tokens least privilege; no unsafe auto-heal or force-push | CI threat model |
| F05 | Signed/hashed downloads, no unaudited pipe-to-shell | Provenance |
| F06 | Image digest pinning and deployed release provenance | Image ID vs committed image |
| F07 | No blind exclusions of agent/skill/workflow directories | Coverage manifest |
| F08 | Regression-test healing/rollback against payload reintroduction | Controlled replay |

## G. Proxy, egress, runtime

| ID | Check | Required verification |
|---|---|---|
| G01 | Origin bypass and unauthorized open services | Exposure map |
| G02 | NGINX/Apache/IIS/Envoy enabled modules and protocols | Live binary/config |
| G03 | Management-plane keys cannot be mounted in app containers | Mount policy |
| G04 | Unexpected shell children, privilege escalation, exfil behavior | EDR/auditd/Wazuh/Falco events |
| G05 | New outbound destinations and unusual connections | Sanitized egress |
| G06 | Admin consoles/metrics/DB publicly exposed? | Network and auth review |
| G07 | Running bundle/service/config match trusted release | Build/digest evidence |

### Effective exposure (not merely source declarations)

| ID | Check | Required verification |
|---|---|---|
| G08 | Host-published database, metrics, admin and debug ports effectively restricted | Live bind/firewall/reachability, not Compose `ports:` alone |
| G09 | Verify placeholder/default passwords are **not active** | Secure config/rotation attestation; never print secrets |

## H. Incident response and gate integrity

| ID | Check | Required verification |
|---|---|---|
| H01 | Document containment/credential theft/root compromise process | Playbook |
| H02 | Evidence snapshots before cleanup | Chain of custody |
| H03 | Attempt vs suspected vs confirmed compromise | Independent verification |
| H04 | Rebuild from trusted image and test clean restore | Recovery drill |
| H05 | Missing/failed checks are UNKNOWN, not safe | Coverage report |
| H06 | Human authority for production changes | Approval |
| H07 | Independently verify patched running deployment | Post-fix proof |
| H08 | Inject malicious fake advisories and malformed data into tests | Negative security tests |
| H09 | Store model, prompt/tool versions and evidence checksums | Audit manifest |
| H10 | Monitor collector uptime, config drift and lost telemetry | Heartbeat |

### Agentic triage and evidence integrity

| ID | Check | Required verification |
|---|---|---|
| H11 | Hash sanitized advisory/assets/checklist and pin worker prompt/tool version | SHA-256 manifest plus scope |
| H12 | Deterministically validate AI findings and adversarially test malicious feed/HTML input | Schema gate + negative fixtures |
| H13 | Keep runtime verification separate from merged source PRs and remote edge observations | Evidence classes; contradictory inputs marked `CONFLICTING` |
| H14 | Clearly report missing KEV/EPSS enrichment, runtime access and regression coverage | Coverage matrix, not silent PASS |

Owned website/webapp assessments also follow [the web application VAPT checklist](webapp-vapt-v1.md) and [the generalized pilot lessons](../docs/agentic-pilot-learnings.md). Its baseline collector does **not** execute the complete catalog.

**Prioritization:** P0 observed compromise or directly exposed urgent exploitable weakness; P1 urgent credible reachable risk; P2 constrained verified exposure; P3 hygiene; UNKNOWN missing evidence. CVSS, KEV and EPSS have distinct meanings.

**Hard rules:** no raw credentials, personal data, unauthorized remote probing, unapproved production edits, shell execution of feed content, or auto-merge. Keep customer reports in private tenant storage.
