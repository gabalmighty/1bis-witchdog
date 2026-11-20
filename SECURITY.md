# Witch Dog security policy

Witch Dog is an experimental security tool.

It does not replace a qualified penetration test, incident response, or endpoint security software.

## Report a security problem

Use GitHub private vulnerability reporting when that feature is available.

Do not post an unpatched exploit in a public issue.

Do not send credentials, client data, hostnames, logs, or private infrastructure records in a public report.

Provide the affected Witch Dog version or commit.

Give a short impact summary and a safe reproduction in an isolated test environment.

## Test only approved systems

Use Witch Dog only on systems that you own or have written authority to test.

Active testing requires an approved scope and safe synthetic data.

Do not run destructive tests or attempt credential theft.

## Keep a safe execution boundary

Do not use a model prompt as the only security boundary.

Keep tools and credentials in an isolated, least-privileged process.

Stop a scan if the plan is invalid or the target is out of scope.

## Disclosure

Allow maintainers to review the issue and prepare a fix before public disclosure.

Use private security channels for the first report.

See [contribution rules](CONTRIBUTING.md) for normal patches.
