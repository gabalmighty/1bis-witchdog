# Security policy

Witch Dog is experimental. The scanner provides bounded evidence and cannot assert complete safety or replace EDR, incident responders, authenticated configuration audits or penetration testing.

**Report vulnerabilities privately.** Use GitHub's **Report a vulnerability** / private vulnerability reporting feature if enabled, or contact the maintainers through a pre-established private channel. Do not file public issues containing exploit details, credentials, incident logs, client names, customer IP addresses or personal data.

Do not attempt intrusive probing of third-party assets. Findings about Witch Dog itself should include an isolated test case, relevant version/commit, expected and observed behavior, and no private secrets.

Before enabling scheduled jobs or remote AI providers, read [Architecture](docs/architecture.md). OpenCode permissions do not provide an OS sandbox. Keep secrets and private repositories out of public GitHub Actions jobs. Production modification always requires explicit operator authorization.
