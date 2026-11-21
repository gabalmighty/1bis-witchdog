#!/usr/bin/env python3
"""Offline developer-supply-chain checks for approved local Git workspaces.

Never executes source, fetches Git remotes, reads .env/credentials, or contacts C2.
The catalog is reviewed local DATA. All matches are candidates, not malware proof.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

VERSION = "0.1.0"
MAX_TEXT = 262144
MAX_LOCK = 4_000_000
MAX_RELEVANT = 120
MAX_FINDINGS = 70
CATALOG = Path(__file__).resolve().parents[1] / "data" / "intel" / "campaigns" / "developer-supply-chain-2026.json"
CONFIG_NAMES = (
    "vite.config.", "react-router.config.", "eslint.config.",
    "next.config.", "postcss.config.", "tailwind.config.",
    "webpack.config.", "babel.config.", "api.js",
)
FONT_SUFFIXES = (".ttf", ".woff", ".woff2", ".orc", ".eot")
KNOWN_HOME = (".npm-ws-runner.js", ".npm-ws.json", ".npm-ws.pid")
NODE_INIT = re.compile(r"\bnode(?:\.exe)?\s+(?:\./)?init\b", re.I)
FOLDEROPEN = re.compile(r"\bfolderOpen\b", re.I)
ENCODED_EVAL = re.compile(r"\b(?:atob|Buffer\.from)\s*\(", re.I)
EVAL = re.compile(r"\b(?:eval|Function)\s*\(", re.I)
REMOTE = re.compile(r"\b(?:fetch|node-fetch|https?\.request|axios)\b", re.I)
SCRIPT = re.compile(r"(?:\brequire\s*\(|\bmodule\.exports\b|\bprocess\.env\b|\beval\s*\()", re.I)
ENV_REINCLUDE = re.compile(r"^\s*!\s*/?\.env(?:\.[^#\s]+)?\s*(?:#.*)?$", re.I)


def path_text(value: str) -> str:
    """Strip Markdown/control characters from evidence. No file contents."""
    return "".join(c if c.isprintable() and c not in ("|", chr(96))
                   else "_" for c in str(value).replace("\n", " ").replace("\r", " "))[:230]


def allowed_path(value: str) -> bool:
    p = Path(value.replace("\\", "/"))
    return (bool(value) and not p.is_absolute() and
            all(x not in ("", ".", "..") for x in p.parts) and
            len(p.parts) <= 9 and len(value) <= 300)


def bounded_bytes(repo: Path, name: str, max_bytes=MAX_TEXT) -> bytes | None:
    if not allowed_path(name):
        return None
    item = repo.joinpath(*Path(name.replace("\\", "/")).parts)
    try:
        if item.is_symlink() or not item.is_file():
            return None
        if item.stat().st_size > max_bytes:
            return None
        return item.read_bytes()
    except (OSError, ValueError):
        return None


def bounded_text(repo: Path, name: str, max_bytes=MAX_TEXT) -> str | None:
    raw = bounded_bytes(repo, name, max_bytes)
    return raw.decode("utf-8", "replace") if raw is not None else None


def finding(control: str, path: str, reason: str, *, risk="REVIEW",
            confidence="PATTERN_CANDIDATE", line: int | None = None) -> dict:
    evidence = path_text(path) + (":" + str(line) if line else "")
    return {
        "control": control, "status": "WARN", "evidence": evidence,
        "reason": reason, "evidence_class": "SOURCE_DECLARED",
        "risk_hint": risk, "confidence": confidence,
        "verification": "REQUIRES_INDEPENDENT_REVIEW",
    }


def catalog_versions() -> set[tuple[str, str]]:
    raw = CATALOG.read_bytes()
    if not 0 < len(raw) <= 20000:
        raise ValueError("Reviewed threat catalog exceeds size limit")
    document = json.loads(raw)
    if (not isinstance(document, dict) or document.get("schema_version") != 1
            or document.get("id") != "developer-supply-chain-2026"):
        raise ValueError("Unknown threat catalog")
    entries = document.get("npm_exact_releases")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 100:
        raise ValueError("Malformed npm threat release list")
    releases = set()
    for entry in entries:
        if (not isinstance(entry, dict) or
                not isinstance(entry.get("package"), str) or
                not isinstance(entry.get("version"), str) or
                len(entry["package"]) > 120 or len(entry["version"]) > 70):
            raise ValueError("Invalid threat release record")
        releases.add((entry["package"], entry["version"]))
    return releases


def locked_packages(raw: bytes) -> set[tuple[str, str]]:
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("Invalid package-lock JSON")
    found = set()
    entries = document.get("packages", {})
    if not isinstance(entries, dict) or len(entries) > 15000:
        raise ValueError("Too many npm lock entries")
    for raw_name, info in entries.items():
        if not isinstance(raw_name, str) or not isinstance(info, dict):
            continue
        if "node_modules/" not in raw_name:
            continue
        name = raw_name.rsplit("node_modules/", 1)[-1]
        if name and isinstance(info.get("version"), str):
            found.add((name, info["version"]))
    # V1 package-lock stores resolved versions in a dependency map.
    deps = document.get("dependencies", {})
    def visit(tree: dict, depth: int = 0) -> None:
        if depth > 6 or len(tree) > 15000:
            return
        for name, info in tree.items():
            if not isinstance(name, str) or not isinstance(info, dict):
                continue
            if isinstance(info.get("version"), str):
                found.add((name, info["version"]))
            nested = info.get("dependencies", {})
            if isinstance(nested, dict):
                visit(nested, depth + 1)
    if isinstance(deps, dict):
        visit(deps)
    return found


def scan_repo(repo: Path, tracked_files: list[str] | None) -> dict:
    """Inspect local worktree/index-backed names. No history or remote access."""
    repo = Path(repo)
    entries = {x.replace("\\", "/") for x in (tracked_files or [])
               if isinstance(x, str) and allowed_path(x)}
    # Include only known high-signal files even if untracked.
    for name in ("package.json", "package-lock.json", ".gitignore",
                 ".vscode/tasks.json", ".vscode/settings.json", "init",
                 "temp_auto_push.bat", "config.bat"):
        item = repo / name
        try:
            if not item.is_symlink() and item.is_file():
                entries.add(name)
        except OSError:
            pass
    findings = []
    checked = 0
    gaps = [
        "Remote Git branches, local non-current refs and Git history NOT_INSPECTED",
        "Running processes, startup entries and unknown persistence NOT_INSPECTED",
        "Only selected local paths and npm lockfiles checked; clean result is NOT host clearance",
    ]
    def add(code, p, why, *, risk="REVIEW", conf="PATTERN_CANDIDATE", line=None):
        if len(findings) < MAX_FINDINGS:
            item = finding(code, p, why, risk=risk, confidence=conf, line=line)
            if not any(x["control"] == item["control"] and
                       x["evidence"] == item["evidence"] for x in findings):
                findings.append(item)

    manifest = sorted(x for x in entries if x.endswith("package.json")
                      and "node_modules/" not in x)[:25]
    for name in manifest:
        raw = bounded_text(repo, name)
        if raw is None:
            gaps.append("Unscanned or oversized package.json in selected scope")
            continue
        checked += 1
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError):
            gaps.append("Unable to parse a selected package.json")
            continue
        scripts = obj.get("scripts", {}) if isinstance(obj, dict) else {}
        if not isinstance(scripts, dict):
            continue
        for k, v in list(scripts.items())[:100]:
            if isinstance(v, str) and NODE_INIT.search(v):
                add("M01", name + ":scripts." + str(k),
                    "Node startup script invokes local init loader; inspect file in isolation",
                    risk="HIGH")

    task_name = ".vscode/tasks.json"
    task_raw = bounded_text(repo, task_name)
    if task_raw is not None:
        checked += 1
        try:
            # VS Code tasks.json may contain JSONC comments; a parse failure is not clearance.
            data = json.loads(task_raw)
            tasks = data.get("tasks", []) if isinstance(data, dict) else []
            if not isinstance(tasks, list):
                tasks = []
            for i, task in enumerate(tasks[:60]):
                if not isinstance(task, dict):
                    continue
                run_options = task.get("runOptions", {})
                folder_open = (isinstance(run_options, dict) and
                               run_options.get("runOn") == "folderOpen")
                if not folder_open:
                    continue
                raw_cmd = str(task.get("command", ""))
                concealed = (task.get("hide") is True or
                             (isinstance(task.get("presentation"), dict) and
                              task["presentation"].get("reveal") == "never"))
                masquerade = bool(re.search(
                    r"\bnode(?:\.exe)?\b.{0,150}\.(?:orc|ttf|woff2?|eot)\b",
                    raw_cmd, re.I))
                add("M02", task_name + ":task" + str(i + 1),
                    "Folder-open task executes automatically; hidden asset loader pattern needs review"
                    if concealed or masquerade else
                    "Folder-open task may execute code; inspect command and workspace trust",
                    risk="HIGH" if concealed and masquerade else "REVIEW")
        except (ValueError, TypeError):
            # A JSONC file may still have a valid folderOpen task.
            if FOLDEROPEN.search(task_raw):
                add("M02", task_name, "Folder-open task present; JSONC needs independent review",
                    risk="REVIEW")
            else:
                gaps.append("VS Code tasks file could not be parsed")
    settings = bounded_text(repo, ".vscode/settings.json")
    if settings and re.search(r'["\x27]task\.allowAutomaticTasks["\x27]\s*:\s*true', settings):
        checked += 1
        add("M02", ".vscode/settings.json",
            "Workspace explicitly enables automatic tasks; check task definitions")

    cfg = sorted(x for x in entries
                 if any(Path(x).name.lower().startswith(n) for n in CONFIG_NAMES)
                 and Path(x).suffix.lower() in (".ts", ".mts", ".js", ".mjs", ".cjs"))[:45]
    for name in cfg:
        content = bounded_text(repo, name)
        if content is None:
            gaps.append("A relevant build or lint config was skipped")
            continue
        checked += 1
        if EVAL.search(content) and ENCODED_EVAL.search(content) and (
                "AUTH_API_KEY" in content or REMOTE.search(content)):
            add("M04", name, "Config decodes and executes dynamic content; verify provenance",
                risk="HIGH")
        elif EVAL.search(content) and REMOTE.search(content):
            add("M06", name, "Config has network and code-evaluation traits; inspect data flow",
                risk="REVIEW")
    ignore = bounded_text(repo, ".gitignore")
    if ignore is not None:
        checked += 1
        for n, line in enumerate(ignore.splitlines(), 1):
            if ENV_REINCLUDE.match(line) and not re.search(
                    r"\.(?:example|sample|template|dist)\b", line, re.I):
                add("M05", ".gitignore", "Git ignore rules reinclude a private env file",
                    risk="HIGH", line=n)
                break

    font_paths = sorted(x for x in entries if
                        Path(x).suffix.lower() in FONT_SUFFIXES and
                        ("/fonts/" in "/" + x.lower() or x.lower().endswith(".orc")))[:35]
    for name in font_paths:
        raw = bounded_bytes(repo, name, max_bytes=160000)
        if raw is None:
            gaps.append("Oversized or missing font-like asset was not inspected")
            continue
        checked += 1
        recognized = (raw.startswith((b"wOFF", b"wOF2", b"OTTO", b"\x00\x01\x00\x00"))
                      or raw.startswith(b"ttcf"))
        if not recognized and SCRIPT.search(raw[:16000].decode("utf-8", "replace")):
            add("M03", name,
                "Font-like asset contains executable-source traits, not a known font header",
                risk="HIGH")
    for name in ("init", "temp_auto_push.bat"):
        raw = bounded_bytes(repo, name)
        if raw is None:
            continue
        checked += 1
        if name == "temp_auto_push.bat":
            add("M09", name, "Unusual automated Git push script; inspect provenance",
                risk="HIGH")
        elif SCRIPT.search(raw[:16000].decode("utf-8", "replace")):
            add("M01", name, "Root init file has source-code traits; check launch path",
                risk="REVIEW")

    lock_files = sorted(x for x in entries if
                        x == "package-lock.json" or x.endswith("/package-lock.json"))[:10]
    checked_locks = 0
    try:
        releases = catalog_versions()
    except (OSError, ValueError, TypeError):
        releases = set()
        gaps.append("Reviewed malicious-package catalog unavailable; M08 UNKNOWN")
    if not lock_files:
        gaps.append("No package-lock.json in local worktree; other lock formats NOT_INSPECTED")
    for name in lock_files:
        raw = bounded_bytes(repo, name, max_bytes=MAX_LOCK)
        if raw is None:
            gaps.append("npm lockfile skipped or over byte limit")
            continue
        checked += 1
        checked_locks += 1
        try:
            installed = locked_packages(raw)
        except (ValueError, TypeError, RecursionError):
            gaps.append("npm lockfile malformed; versions UNKNOWN")
            continue
        for pkg, version in sorted(installed & releases):
            add("M08", name + ":" + pkg,
                "Exact published malicious npm release " + pkg + "@" + version +
                " in lockfile; execution and installed artifact UNKNOWN", risk="HIGH",
                conf="PUBLISHED_VERSION_MATCH")
    if len(findings) >= MAX_FINDINGS:
        gaps.append("Finding limit reached; review is PARTIAL")
    return {
        "schema_version": 1, "version": VERSION,
        "status": "SUSPECTED" if findings else "NO_INDICATOR_IN_CHECKED_PATHS",
        "findings": findings, "checked_files": checked, "checked_npm_locks": checked_locks,
        "coverage_gaps": gaps, "network_requests": 0, "target_code_executed": False,
        "scope": "LOCAL_WORKTREE_AND_TRACKED_NAMES_ONLY",
    }


def scan_home(home: Path | None = None) -> dict:
    """Check known artifact filenames only. Never read their content."""
    base = Path.home() if home is None else Path(home)
    folder = base / ".node_modules"
    if folder.is_symlink():
        return {
            "status": "UNKNOWN", "artifact_names": [], "paths_checked": 0,
            "evidence_class": "HOST_OBSERVED",
            "note": "Home staging folder is a symlink; not followed.",
        }
    present = []
    for name in KNOWN_HOME:
        try:
            p = folder / name
            if not p.is_symlink() and p.is_file():
                present.append(name)
        except OSError:
            continue
    return {
        "status": "SUSPECTED" if present else "NOT_DETECTED_IN_CHECKED_PATHS",
        "artifact_names": present,
        "paths_checked": len(KNOWN_HOME),
        "evidence_class": "HOST_OBSERVED",
        "note": ("Filename observations only; process, network and persistence "
                 "not tested; absence is NOT proof of a clean host."),
    }
