# Disposable VM mode: acceptance criteria (NOT IMPLEMENTED)

Witch Dog v0.1 supplies an environment/capability preflight. It **does not** create, connect to, or destroy VMs. Do not interpret a successful capability probe as authority to manipulate the virtualization host.

## Recommended job sequence

1. Record written approval for the repository, branch, host, VM template and tests. Record CPU, memory, disk, network, expiry and cost limits.
2. Check hypervisor access, spare capacity, a trusted VM image and read-only Git access. Check the job ID, report location, quota and cleanup authority. Save dry-run proof.
3. Create a **new** disposable VM from an immutable, scanned image; never reuse a client production VM or mount host secrets. Disable access to production network, Hyper-V management interfaces and unrestricted outbound internet.
4. Clone approved Git ref pinned to a SHA. Use read-only scoped credentials. Treat repo build scripts, hooks and dependencies as hostile; restrict network and VM privileges.
5. Run deterministic tests, then model investigation in separate isolated context. Export sanitized, integrity-checked reports.
6. If authorized for source fixes, write to a **different** short-lived Git branch using PR-only credentials. Never give the test VM a broadly scoped admin token or production deploy credential.
7. Verify report schema/absence of secrets; upload evidence to a tenant-private destination.
8. **Cleanup:** Destroy only the VM that matches the recorded job ID. Preserve necessary evidence. Verify removal and save the result. Never destroy a preexisting VM.

## Fail-closed prerequisites

- **HOLD** if host identity, approval, image signature, ownership, capacity, Git access or cleanup proof is missing. Do not contact a production network.
- Never run arbitrary test commands directly on the host as a fallback.
- Never log secrets in provisioning metadata or a PR.
- On incident indicators, suspend automated cleanup and follow the evidence-preservation policy with operator authorization.

## Backends

Windows Hyper-V, Linux KVM/libvirt and cloud ephemeral VMs are potential future backends. Each requires an independently reviewed provider adapter and integration tests. Docker containers are **not equivalent to isolated VMs**.

See `python tools/witchdog.py preflight --backend hyperv` (or `libvirt`) for a **non-provisioning** capability preview.
