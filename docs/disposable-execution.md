# Disposable VM mode: acceptance criteria (NOT IMPLEMENTED)

Witch Dog v0.1 supplies an environment/capability preflight. It **does not** create, connect to, or destroy VMs. Do not interpret a successful capability probe as authority to manipulate the virtualization host.

## Recommended job sequence

1. Collect explicit operator authorization: allowed repository/branch, host/hypervisor, VM template, CPU/RAM/disk limit, network restrictions, time-to-live, test classes and cost ceiling.
2. Verify prerequisites with read-only commands: required hypervisor CLI available, sufficient unreserved capacity, secure template digest, authentication to *read-only* source, unique job ID, storage for report/PR, quota and cleanup authority. Require explicit dry-run proof.
3. Create a **new** disposable VM from an immutable, scanned image; never reuse a client production VM or mount host secrets. Disable access to production network, Hyper-V management interfaces and unrestricted outbound internet.
4. Clone approved Git ref pinned to a SHA. Use read-only scoped credentials. Treat repo build scripts, hooks and dependencies as hostile; restrict network and VM privileges.
5. Run deterministic tests, then model investigation in separate isolated context. Export sanitized, integrity-checked reports.
6. If authorized for source fixes, write to a **different** short-lived Git branch using PR-only credentials. Never give the test VM a broadly scoped admin token or production deploy credential.
7. Verify report schema/absence of secrets; upload evidence to a tenant-private destination.
8. **Cleanup:** destroy only the VM whose unique job ID was recorded by the provisioning operation, even on failure/timeout, after preserving needed forensic evidence. Never destroy an unknown/preexisting VM. Verify removal and record cleanup proof.

## Fail-closed prerequisites

- Unknown virtualization host, absent permissions, unsigned/untrusted base image, existing production network routes, unknown workspace ownership, insufficient capacity, absent scoped Git credentials, inability to attribute disposable resources, or unverified cleanup: **HOLD**.
- Never run arbitrary test commands directly on the host as a fallback.
- Never log secrets in provisioning metadata or a PR.
- On incident indicators, suspend automated cleanup and follow the evidence-preservation policy with operator authorization.

## Backends

Windows Hyper-V, Linux KVM/libvirt and cloud ephemeral VMs are potential future backends. Each requires an independently reviewed provider adapter and integration tests. Docker containers are **not equivalent to isolated VMs**.

See \`python tools/witchdog.py preflight --backend hyperv\` (or \`libvirt\`) for a **non-provisioning** capability preview.
