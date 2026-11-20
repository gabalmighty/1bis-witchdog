#!/usr/bin/env python3
"""Find long sentences in public Markdown.

This is an ASD-STE100-inspired check, NOT a full STE compliance checker.
It does not check the controlled dictionary or all grammar rules.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

WORD = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9'-]*\b")
LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
TICK = chr(96)
CODE = re.compile(TICK + r"[^" + TICK + r"]*" + TICK)
URL = re.compile(r"https?://\S+")
SENTENCE = re.compile(r"(?<=[.!?])(?:\s+|$)")
MAX_ISSUES = 200


def checks(path: Path) -> list[dict]:
    if not path.is_file() or path.stat().st_size > 200_000:
        raise ValueError("Input document is missing or too large")
    issues = []
    fenced = False
    for n, raw in enumerate(path.read_text("utf-8").splitlines(), 1):
        line = raw.strip()
        if line.startswith((TICK * 3, "~~~")):
            fenced = not fenced
            continue
        if fenced or not line or line.startswith(
            ("#", "|", "<", "![", "---", "===")
        ) or raw.startswith("    "):
            continue
        text = LINK.sub(r"\1", line)
        text = CODE.sub(" CODE ", text)
        text = URL.sub(" URL ", text)
        text = re.sub(r"\*\*|__", "", text)
        limit = 20 if re.match(r"^\d+\.\s+", text) else 25
        text = re.sub(r"^(?:[-*+]\s+|\d+\.\s+)", "", text)
        for sentence in SENTENCE.split(text):
            words = len(WORD.findall(sentence))
            if words > limit:
                issues.append({
                    "line": n, "words": words, "max_words": limit,
                    "rule": "LONG_SENTENCE",
                })
                if len(issues) >= MAX_ISSUES:
                    return issues
    return issues


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check concise Markdown prose")
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--all", action="store_true", help="Scan all public Markdown")
    parser.add_argument("--advisory", action="store_true",
                        help="Report style debt but exit successfully")
    args = parser.parse_args(argv)
    paths = list(args.paths)
    if args.all:
        paths.extend(Path(".").glob("*.md"))
        paths.extend(Path("docs").rglob("*.md"))
        paths.extend(Path("checklists").rglob("*.md"))
    if not paths:
        parser.error("Select Markdown files or use --all")
    results = {}
    try:
        for path in dict.fromkeys(paths):
            results[str(path)] = checks(path)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "HOLD", "reason": type(exc).__name__}))
        return 2
    count = sum(len(x) for x in results.values())
    # Keep CI logs short. Show the first eight issues per document.
    previews = {key: {"count": len(val), "first": val[:8]}
                for key, val in results.items() if val}
    print(json.dumps({"status": "PASS" if not count else "STYLE_REVIEW",
                      "issues": count, "files_checked": len(results),
                      "files_with_issues": previews}, indent=2))
    return 0 if not count or args.advisory else 2


if __name__ == "__main__":
    sys.exit(main())
