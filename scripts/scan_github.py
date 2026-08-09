#!/usr/bin/env python3
"""Reproduce the large-scale GitHub scan documented in GITHUB_SCAN_RESULTS.md.

Uses the GitHub code search API to find real, public SKILL.md files across
all of GitHub, downloads each one, and runs it through skillsmith's parser,
linter, and security-scan heuristics. Requires a GitHub token with
`public_repo` (or no scopes at all works for public code search) set as
GH_TOKEN, because GitHub's code search API requires authentication.

Usage:
    GH_TOKEN=ghp_... python scripts/scan_github.py --sample-size 400
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from skillsmith import lint as sl
from skillsmith import scan as ss


def raw_url_from_html(html_url: str):
    m = re.match(r"https://github.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)", html_url)
    if not m:
        return None
    owner, repo, ref, path = m.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"


def search_skill_md_files(token: str, sample_size: int) -> list[dict]:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    items: list[dict] = []
    page = 1
    while len(items) < sample_size and page <= 10:
        r = requests.get(
            "https://api.github.com/search/code",
            params={"q": "filename:SKILL.md", "per_page": 100, "page": page},
            headers=headers,
            timeout=30,
        )
        if r.status_code != 200:
            print(f"search stopped at page {page}: {r.status_code} {r.text[:200]}", file=sys.stderr)
            break
        items.extend(r.json().get("items", []))
        page += 1
        time.sleep(2.2)  # code search is rate limited (~10-30 req/min)
    seen = set()
    unique = []
    for it in items:
        if it["html_url"] in seen:
            continue
        seen.add(it["html_url"])
        unique.append(it)
    return unique[:sample_size]


def fetch_contents(items: list[dict]) -> list[dict]:
    out = []
    for it in items:
        url = raw_url_from_html(it["html_url"])
        if not url:
            continue
        try:
            r = requests.get(url, timeout=10)
        except requests.RequestException:
            continue
        if r.status_code == 200 and len(r.text) < 200_000:
            out.append({"html_url": it["html_url"], "text": r.text})
    return out


def analyze(contents: list[dict]) -> list[dict]:
    results = []
    for c in contents:
        try:
            fm, body = sl.parse_skill_md(c["text"])
            parse_ok = True
        except sl.SkillParseError:
            fm, body, parse_ok = {}, "", False

        lint_issues = []
        if parse_ok:
            for key in sl.REQUIRED_KEYS:
                if not fm.get(key):
                    lint_issues.append(f"missing-field:{key}")
            if not body.strip():
                lint_issues.append("empty-body")

        injection = ss._scan_text(c["text"], "raw", ss._PROMPT_INJECTION_PATTERNS)
        code = ss._scan_text(c["text"], "raw", ss._CODE_PATTERNS)

        results.append(
            {
                "html_url": c["html_url"],
                "parse_ok": parse_ok,
                "lint_issues": lint_issues,
                "injection_flags": [f.message for f in injection],
                "code_pattern_flags": [f.message for f in code],
            }
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-size", type=int, default=400)
    parser.add_argument("--out", default="github_scan_raw_results.json")
    args = parser.parse_args()

    token = os.environ.get("GH_TOKEN")
    if not token:
        print("Set GH_TOKEN to a GitHub token (public code search requires auth).", file=sys.stderr)
        return 1

    print(f"Searching GitHub for SKILL.md files (target sample: {args.sample_size})...")
    items = search_skill_md_files(token, args.sample_size)
    print(f"Found {len(items)} unique candidate files, downloading...")
    contents = fetch_contents(items)
    print(f"Downloaded {len(contents)} files, analyzing...")
    results = analyze(contents)

    Path(args.out).write_text(json.dumps(results, indent=2), encoding="utf-8")

    n = len(results)
    n_fail = sum(1 for r in results if not r["parse_ok"])
    n_lint = sum(1 for r in results if r["lint_issues"])
    n_inj = sum(1 for r in results if r["injection_flags"])
    n_code = sum(1 for r in results if r["code_pattern_flags"])
    print(f"\n{n} real public SKILL.md files analyzed:")
    print(f"  {n_fail} failed to parse as valid frontmatter+body")
    print(f"  {n_lint} had lint issues (missing required fields, empty body)")
    print(f"  {n_inj} matched prompt-injection heuristics")
    print(f"  {n_code} matched dangerous-code heuristics (in embedded code blocks)")
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
