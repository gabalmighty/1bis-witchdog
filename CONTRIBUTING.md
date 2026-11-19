# Contributing

Welcome! This is an intentionally small, auditable, platform-agnostic project.

1. Open an issue for new scanners, threat feeds or checks. Include trustworthy primary sources and false-positive/negative cases.
2. Create a feature branch; write deterministic checks with tests and bounded I/O; submit a PR.
3. Preserve read-only default, no customer-data collection and \`UNKNOWN\` for missing evidence.
4. Do not add dynamic shell execution of advisory content, auto-remediation of production, CI secrets to untrusted workflows or new privileged dependencies without independent review.
5. Run \`python3 -m unittest discover -s tests -v\` and \`python3 -m compileall -q tools\`. On Windows, use \`py -3\`.

All source code and artwork you contribute must be appropriately licensed for inclusion under [MIT](LICENSE). Never contribute private client evidence, machine credentials, internal infrastructure names, proprietary reports or malware payloads.

Good starter contributions: reliable Windows capability probes, offline SBOM parsers, vendor backport matching, automated normalization regression fixtures, sanitized report schemas and disposable-VM implementation behind an explicit approval gate.
