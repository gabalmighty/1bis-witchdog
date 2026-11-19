#!/usr/bin/env python3
"""Publish/update one Witch Dog bot PR review AFTER the model subprocess exits.

Do not invoke this module from inside OpenCode. Separate token only here.
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

MARKER = "<!-- witchdog-pr-review:v1 -->"
RE_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
RE_SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_COMMENT = 48000

def api(method, repo, route, token, payload=None):
    url = "https://api.github.com/repos/" + repo + "/" + route
    data = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None
    request = urllib.request.Request(url, method=method, data=data, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "Content-Type": "application/json", "User-Agent": "WitchDog-PR-Review/0.1",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(1_500_001)
        if len(raw) > 1_500_000:
            raise ValueError("GitHub API response oversized")
        return json.loads(raw.decode())

def author_may_update(comment):
    user = comment.get("user") or {}
    # Only GitHub's known Actions bot, not a user who spoofed our marker.
    return user.get("login") == "github-actions[bot]" and user.get("type") == "Bot"

def choose_action(comments):
    for comment in reversed(comments):
        if MARKER in str(comment.get("body", "")) and author_may_update(comment):
            return ("PATCH", "issues/comments/" + str(comment["id"]))
    return ("POST", None)

def publish(repo, pr, expected_sha, output, *, token):
    if not RE_REPO.fullmatch(repo) or not 1 <= pr <= 2_000_000:
        raise ValueError("Invalid repository or PR")
    if not RE_SHA.fullmatch(expected_sha):
        raise ValueError("Expected head SHA must be 40 hex characters")
    if not token or len(token) < 10:
        raise ValueError("GitHub token required only for publisher")
    report = json.loads((output / "inspection.json").read_text("utf-8"))
    body = (output / "review.md").read_text("utf-8")
    if report.get("head") != expected_sha or MARKER not in body:
        raise ValueError("Review report/HEAD mismatch")
    if report.get("status") not in ("REVIEWED", "PARTIAL"):
        raise ValueError("Review has no valid scan state")
    if len(body) > MAX_COMMENT:
        raise ValueError("Review comment too large")
    # Avoid unsolicited PR notifications from malicious model text.
    body = re.sub(r"(?<![A-Za-z0-9_])@(?=[A-Za-z0-9_])", "@\u200b", body)
    pr_data = api("GET", repo, "pulls/" + str(pr), token)
    if (pr_data.get("state") != "open" or
            (pr_data.get("head") or {}).get("sha") != expected_sha or
            ((pr_data.get("head") or {}).get("repo") or {}).get("full_name") != repo):
        raise ValueError("PR stale, closed or from fork; refuse publication")
    comments = []
    for page in range(1, 11):
        page_data = api("GET", repo,
                        "issues/" + str(pr) + "/comments?per_page=100&page=" + str(page), token)
        if not isinstance(page_data, list):
            raise ValueError("Unexpected GitHub comments response")
        comments.extend(page_data)
        if len(page_data) < 100:
            break
    method, path = choose_action(comments)
    if method == "POST":
        path = "issues/" + str(pr) + "/comments"
    result = api(method, repo, path, token, {"body": body})
    return {"operation": "UPDATED" if method == "PATCH" else "CREATED",
            "comment_id": result.get("id"), "head": expected_sha, "status": report["status"]}

def main():
    p = argparse.ArgumentParser(description="Publish Witch Dog review using scoped GitHub token")
    p.add_argument("--repo", required=True)
    p.add_argument("--pr", required=True, type=int)
    p.add_argument("--head", required=True)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    try:
        token = os.environ.get("GITHUB_TOKEN", "")
        result = publish(args.repo, args.pr, args.head.lower(), args.out, token=token)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, urllib.error.HTTPError,
            urllib.error.URLError) as exc:
        print("Witch Dog publish HOLD: " + type(exc).__name__, file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
