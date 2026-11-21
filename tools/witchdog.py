#!/usr/bin/env python3
"""Witch Dog: read-only, bounded host and multi-Git-repository inventory."""
import argparse
import datetime
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

VERSION = "0.3.0"
SKIP = {".git", ".witchdog", "node_modules", ".venv", "venv", ".next",
        "__pycache__", "dist", "build", "vendor", "target", ".terraform"}
SECRET = re.compile(r"(^|/)(\.env(?:\.[^/]*)?|\.npmrc|id_rsa|id_ed25519|[^/]*\.(?:pem|p12|pfx|key))$", re.I)
EXAMPLE = re.compile(r"\.(?:example|sample|template|dist)$", re.I)
DEV = re.compile(r"(?:--host(?:=|\s+)(?:0\.0\.0\.0|::)|(?:vite|react-router)\s+dev\s+--host(?:\s|$))", re.I)
PUBLIC = re.compile(r"(?:\.(?:sql|dump|har|pem|key|p12|pfx)$|(?:^|[/_-])(?:backup|payroll|private|credential|export)(?:[/_.-]|$))", re.I)

def safe(s, limit=200):
    return "".join(c if c.isprintable() and c not in ("|", chr(96)) else "_"
                   for c in str(s)).replace("\r", " ").replace("\n", " ")[:limit]

def small(path):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 262144:
            return None
        return path.read_text("utf-8", errors="replace")
    except OSError:
        return None

def developer_guard_module():
    """Load only the trusted Witch Dog module, never a file in the target repo."""
    path = Path(__file__).resolve().with_name("developer_guard.py")
    spec = importlib.util.spec_from_file_location("_witchdog_developer_guard", path)
    if spec is None or spec.loader is None:
        raise ValueError("Developer malware guard unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def host():
    system = platform.system()
    hints = []
    if os.getenv("WSL_DISTRO_NAME") or "microsoft" in platform.release().lower():
        hints.append("WSL_HINT")
    if system == "Linux" and (Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()):
        hints.append("CONTAINER_HINT")
    if os.getenv("CI", "").lower() in ("true", "1"):
        hints.append("CI_HINT")
    if system == "Linux":
        for f in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"):
            value = small(Path(f))
            if value and re.search(r"hyper-v|virtual machine|kvm|qemu|vmware|xen", value, re.I):
                hints.append("VM_DMI_HINT")
                break
    tools = ["git", "python", "python3", "docker", "kubectl", "virsh", "qemu-img",
             "powershell", "pwsh", "opencode"]
    try:
        malware_artifacts = developer_guard_module().scan_home()
    except (OSError, ValueError, TypeError):
        malware_artifacts = {
            "status": "UNKNOWN", "artifact_names": [], "paths_checked": 0,
            "note": "Developer loader filename checks were unavailable",
        }
    return {
        "evidence_class": "HOST_OBSERVED", "system": system,
        "release": safe(platform.release(), 70), "architecture": safe(platform.machine(), 50),
        "signals_not_proof": hints,
        "tools_present_not_authorized": {x: bool(shutil.which(x)) for x in tools},
        "running_services": "NOT_INSPECTED", "guests": "NOT_INSPECTED",
        "remote_hosts": "NOT_INSPECTED",
        "developer_loader_artifacts": malware_artifacts,
    }

def discover(root, max_repos=25, depth_limit=4):
    if root.is_symlink() or not root.is_dir() or root == Path(root.anchor):
        raise ValueError("Choose an existing non-symlink directory, not a drive root")
    found, gaps, count = [], [], 0
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        count += 1
        here = Path(base)
        depth = len(here.relative_to(root).parts)
        if count > 15000:
            gaps.append("Directory budget exhausted")
            break
        if ".git" in dirs or ".git" in files:
            found.append(here)
            if len(found) >= max_repos:
                gaps.append("Repository budget exhausted")
                break
        dirs[:] = sorted(n for n in dirs if n not in SKIP
                         and not (here / n).is_symlink() and depth < depth_limit)
    return found, gaps

def tracked(repo):
    if not shutil.which("git"):
        return None
    try:
        res = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"],
                             cwd=repo, capture_output=True, timeout=12, check=False)
        if res.returncode or len(res.stdout) > 2_000_000:
            return None
        return [b.decode("utf-8", errors="replace").replace("\\", "/")
                for b in res.stdout.split(b"\0") if b][:10000]
    except (OSError, subprocess.TimeoutExpired):
        return None

def finding(items, code, status, evidence, why):
    if len(items) < 120:
        items.append({"control": code, "status": status, "evidence": safe(evidence),
                      "reason": safe(why, 300), "evidence_class": "SOURCE_DECLARED"})

def inspect(repo, root):
    files = tracked(repo)
    out = []
    if files is None:
        finding(out, "F01", "UNKNOWN", ".git", "Git index unavailable; source coverage incomplete")
        files = []
    else:
        sensitive = [p for p in files if SECRET.search(p) and not EXAMPLE.search(p)]
        for p in sensitive[:15]:
            finding(out, "E01", "FAIL", p, "Tracked secret-like file name; value NOT read")
        if not sensitive:
            finding(out, "E01", "UNKNOWN", "git ls-files",
                    "No secret-like tracked paths; contents, history, branch heads and CI artifacts NOT assessed")
    package_files = [p for p in files if p.endswith("package.json") and
                     len(Path(p).parts) <= 5 and "node_modules" not in p]
    if not package_files and (repo / "package.json").exists():
        package_files = ["package.json"]
    locks = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml",
             "yarn.lock", "bun.lock", "bun.lockb")
    for p in package_files[:25]:
        raw = small(repo / p)
        try:
            pkg = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            finding(out, "B02", "WARN", p, "Malformed package.json; vulnerability comparison unavailable")
            continue
        scripts = pkg.get("scripts", {}) if isinstance(pkg, dict) else {}
        if isinstance(scripts, dict):
            for name, body in list(scripts.items())[:100]:
                if not isinstance(body, str):
                    continue
                if DEV.search(body):
                    finding(out, "A06", "WARN", p + ":scripts." + name,
                            "Potential all-interface dev server; live listener/reachability UNKNOWN")
                if name in ("preinstall", "install", "postinstall", "prepare"):
                    finding(out, "F02", "WARN", p + ":scripts." + name,
                            "Lifecycle execution path needs review; NOT executed")
        if not any((repo / Path(p).parent / l).exists() for l in locks):
            finding(out, "F01", "WARN", p, "No sibling lockfile found; may use workspace root lockfile")
    for p in files:
        if p.startswith("public/") and PUBLIC.search(p):
            finding(out, "E03", "WARN", p, "Filename-only sensitive public file heuristic; no contents inspected")
        if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml")):
            raw = small(repo / p)
            if raw and "pull_request_target" in raw:
                finding(out, "F04", "WARN", p, "Review privileged CI event and untrusted inputs")
        if Path(p).name.lower().startswith("dockerfile"):
            raw = small(repo / p)
            if raw:
                for n, line in enumerate(raw.splitlines(), 1):
                    match = re.match(r"^\s*FROM\s+(.+?)(?:\s+#.*)?$", line, re.I)
                    if not match:
                        continue
                    parts = match.group(1).split()
                    i = 0
                    while i < len(parts) and parts[i].startswith("--"):
                        if parts[i].lower() == "--platform":
                            i += 2
                        else:
                            i += 1
                    image = parts[i] if i < len(parts) else ""
                    if not image or "$" in image or image.startswith("--"):
                        status, reason = ("UNKNOWN",
                            "Dynamic/invalid Docker base image; resolved digest and running image UNKNOWN")
                    elif image.lower() == "scratch":
                        status, reason = ("N/A",
                            "Docker scratch base has no registry digest; running image UNKNOWN")
                    elif re.search(r"@sha256:[a-f0-9]{64}$", image, re.I):
                        status, reason = ("PASS",
                            "Image reference has a SHA-256 digest; source declaration only; running image UNKNOWN")
                    else:
                        status, reason = ("WARN",
                            "Base image lacks a valid SHA-256 digest; source declaration only; running image UNKNOWN")
                    finding(out, "F06", status, p + ":" + str(n), reason)
    if ".gitmodules" in files:
        finding(out, "F01", "WARN", ".gitmodules", "Verify gitlink, tracked branch and built artifact alignment")
    try:
        guard = developer_guard_module().scan_repo(repo, files)
        for item in guard["findings"]:
            if len(out) < 120:
                out.append(item)
    except (OSError, ValueError, TypeError, KeyError):
        guard = {
            "status": "UNKNOWN", "checked_files": 0, "checked_npm_locks": 0,
            "findings": [], "coverage_gaps": ["Developer guard could not run"],
            "scope": "NOT_INSPECTED",
        }
        finding(out, "M00", "UNKNOWN", "developer malware patterns",
                "Developer guard unavailable; no malware-clearance claim")
    finding(out, "A03", "UNKNOWN", "source vs deployed runtime",
            "No authenticated deployed-image/commit/digest evidence was collected")
    finding(out, "A02", "UNKNOWN", "listeners and network reachability",
            "Live service and network probes are not part of this baseline scanner")
    return {"repo": safe(repo.relative_to(root)), "tracked_count": len(files),
            "evidence_class": "SOURCE_DECLARED", "findings": out,
            "developer_guard": {
                "status": guard["status"],
                "checked_files": guard["checked_files"],
                "checked_npm_locks": guard["checked_npm_locks"],
                "coverage_gaps": guard["coverage_gaps"],
                "scope": guard["scope"],
            }}

def report_md(doc):
    lines = ["# Witch Dog local audit", "",
             "> PRIVATE LOCAL REPORT. Do not publish client information in public Witch Dog issues.", "",
             "UTC: " + doc["timestamp_utc"], "",
             "Host: " + safe(doc["host"]["system"]) + " / " + safe(doc["host"]["release"]), "",
             "Running services, guest VMs and remote assets: **NOT INSPECTED**.",
             "Known home loader artifacts: " +
             safe(doc["host"].get("developer_loader_artifacts", {}).get("status", "UNKNOWN")),
             ""]
    for gap in doc["coverage_gaps"]:
        lines.append("- Coverage gap: " + safe(gap))
    for repo in doc["repos"]:
        lines.extend(["", "## " + repo["repo"], "",
                      "| Control | Status | Evidence | Explanation |", "|---|---|---|---|"])
        for gap in repo.get("developer_guard", {}).get("coverage_gaps", []):
            lines.append("- Developer guard coverage gap: " + safe(gap))
        for item in repo["findings"]:
            lines.append("| " + item["control"] + " | " + item["status"] + " | " +
                         item["evidence"] + " | " + item["reason"] + " |")
    lines += ["", "PASS covers only the narrow listed rule. Missing live evidence remains UNKNOWN.",
              "No secrets were intentionally read. No host configurations were changed.", ""]
    return "\n".join(lines)

def scan(root, output, max_repos):
    root = root.expanduser().resolve(strict=True)
    repos, gaps = discover(root, max_repos=max_repos)
    data = {"schema_version": 1, "version": VERSION,
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "scope": safe(root.name), "host": host(), "repos": [],
            "coverage_gaps": gaps, "action": "READ_ONLY"}
    if not repos:
        data["coverage_gaps"].append("No git roots found in authorized scan scope")
    for path in repos:
        if path.resolve() != Path(__file__).resolve().parents[1]:
            data["repos"].append(inspect(path, root))
    output = output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "scan.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    (output / "report.md").write_text(report_md(data), encoding="utf-8")
    print("Witch Dog scan: %d repositories, %d coverage gaps; %s" %
          (len(data["repos"]), len(gaps), output))
    return 2 if data["coverage_gaps"] else 0

def main():
    p = argparse.ArgumentParser(description="Read-only, bounded Witch Dog host/source inventory")
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="action", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--root", type=Path, required=True)
    s.add_argument("--output", type=Path, required=True)
    s.add_argument("--max-repos", type=int, default=25)
    v = sub.add_parser("preflight", help="No VM is created")
    v.add_argument("--backend", choices=("hyperv", "libvirt"), required=True)
    args = p.parse_args()
    if args.action == "preflight":
        print(json.dumps({"backend": args.backend, "host": host()["system"],
                          "verdict": "HOLD", "vm_created": False,
                          "reason": "Disposable VM provisioning is not implemented in v0.1"}, indent=2))
        return 2
    if not 1 <= args.max_repos <= 250:
        p.error("--max-repos must be between 1 and 250")
    try:
        return scan(args.root, args.output, args.max_repos)
    except (OSError, ValueError) as exc:
        print("Witch Dog HOLD: " + safe(exc), file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
