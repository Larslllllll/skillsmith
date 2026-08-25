"""Command-line interface for skillsmith."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .lint import find_skill_dirs, lint_skill_dir
from .package import package_skill
from .scaffold import scaffold_skill
from .scan import scan_skill_dir
from .lookup import public_scan, sha256_of_file
from .watch import check_watch, create_watch


def _cmd_init(args: argparse.Namespace) -> int:
    dest = Path(args.path) if args.path else Path(args.name)
    scaffold_skill(dest, name=args.name, description=args.description, python_import=args.python_import)
    print(f"Created skill scaffold at {dest}/SKILL.md")
    return 0


def _cmd_lint(args: argparse.Namespace) -> int:
    root = Path(args.path)
    skill_dirs = find_skill_dirs(root)
    if not skill_dirs:
        print(f"No SKILL.md files found under {root}", file=sys.stderr)
        return 1

    exit_code = 0
    for skill_dir in skill_dirs:
        result = lint_skill_dir(skill_dir)
        label = result.frontmatter.get("name", skill_dir)
        if not result.issues:
            print(f"OK   {label} ({skill_dir})")
            continue
        for issue in result.issues:
            print(f"{issue.level.upper():7} {label}: {issue.message}")
        if not result.ok:
            exit_code = 1
    return exit_code


def _cmd_list(args: argparse.Namespace) -> int:
    root = Path(args.path)
    for skill_dir in find_skill_dirs(root):
        result = lint_skill_dir(skill_dir)
        name = result.frontmatter.get("name", "?")
        desc = (result.frontmatter.get("description") or "").strip().splitlines()[0:1]
        desc = desc[0] if desc else ""
        status = "valid" if result.ok else "invalid"
        print(f"{name:30} [{status:7}] {desc[:80]}")
    return 0


def _cmd_package(args: argparse.Namespace) -> int:
    out = package_skill(Path(args.path), Path(args.out) if args.out else None)
    print(f"Wrote {out}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    skill_dirs = find_skill_dirs(root)
    if not skill_dirs:
        print(f"No SKILL.md files found under {root}", file=sys.stderr)
        return 1

    exit_code = 0
    high_risk = 0
    for skill_dir in skill_dirs:
        result = scan_skill_dir(skill_dir)
        lint_result = lint_skill_dir(skill_dir)
        label = lint_result.frontmatter.get("name", skill_dir)
        if not result.findings:
            if args.verbose:
                print(f"clean   {label}")
            continue
        print(f"{result.risk_level.upper():6} risk={result.risk_score:<3} {label} ({skill_dir})")
        for finding in result.findings:
            print(f"        [{finding.source}] {finding.message} (+{finding.weight})")
        if result.risk_level == "high":
            high_risk += 1
            if args.fail_on_high:
                exit_code = 1
    if args.fail_on_high and high_risk:
        print(f"\n{high_risk} high-risk skill(s) found.", file=sys.stderr)
    return exit_code


def _cmd_lookup(args: argparse.Namespace) -> int:
    if args.hash:
        digest = args.hash.strip().lower()
    else:
        path = Path(args.file)
        if not path.exists():
            print(f"file not found: {path}", file=sys.stderr)
            return 1
        digest = sha256_of_file(path)
    try:
        out = public_scan(digest)
    except Exception as e127:  # noqa: BLE001 - CLI surface
        if "503" in str(e127) or "Service Unavailable" in str(e127):
            print("service temporarily unavailable - please retry in a few minutes", file=sys.stderr)
        else:
            print(f"error: {e127}", file=sys.stderr)
        return 1
    if out.get("error"):
        print(f"unknown hash ({digest[:16]}...) - not scanned yet, or scan it at https://skillsmith.ch")
        return 1
    print(f"skill:      {out.get('name') or '(unnamed)'}")
    print(f"risk_level: {out.get('risk_level')}  (risk_score {out.get('risk_score')})")
    print(f"lint_ok: {out.get('lint_ok')}  parse_ok: {out.get('parse_ok')}  seen: {out.get('seen_count')}x")
    if out.get("has_content"):
        print("published: yes (fetchable via /api/skill with an API key)")
    lvl = (out.get("risk_level") or "").lower()
    return 0 if lvl == "clean" else 2


def _cmd_watch(args: argparse.Namespace) -> int:
    api_key = args.api_key or os.environ.get("SKILLSMITH_API_KEY", "")
    if not api_key:
        print("No API key: pass --api-key or set SKILLSMITH_API_KEY (free at https://skillsmith.ch)", file=sys.stderr)
        return 1
    try:
        if args.delete:
            import json as _json
            import urllib.request as _ureq_d
            from urllib.parse import urlencode as _ue_d
            req_d = _ureq_d.Request(
                os.environ.get("SKILLSMITH_API_BASE", "https://skillsmith.ch")
                + "/api/watch?" + _ue_d({"watch_id": args.delete, "api_key": api_key}),
                method="DELETE")
            try:
                with _ureq_d.urlopen(req_d, timeout=30) as resp_d:
                    data = _json.loads(resp_d.read().decode())
            except _ureq_d.HTTPError as e129:
                print(f"error: HTTP {e129.code} (not found or not yours)", file=sys.stderr)
                return 1
            print(f"deleted: {args.delete}" if data.get("deleted") else "nothing deleted")
            return 0
        if args.list:
            from urllib.parse import urlencode
            import json as _json
            import urllib.request as _ureq
            req_l = _ureq.Request(
                os.environ.get("SKILLSMITH_API_BASE", "https://skillsmith.ch")
                + "/api/watch?" + urlencode({"list": 1, "api_key": api_key}))
            with _ureq.urlopen(req_l, timeout=30) as resp_l:
                data = _json.loads(resp_l.read().decode())
            for it in data.get("watches", []):
                print(f"{it.get('watch_id','?'):18} {it.get('last_status') or '?':12} checks={it.get('checks', 0):<4} {it.get('url','')}")
            print(f"({data.get('count', 0)} watch(es))")
            return 0
        if args.watch_id:
            out = check_watch(args.watch_id, api_key)
            status = out.get("status", "?")
            marks = {"changed": "CHANGED", "unchanged": "ok", "unreachable": "unreachable"}
            print(f"{marks.get(status, status):12} {args.watch_id} (checks: {out.get('checks', '?')})")
            if status == "changed":
                print("The watched skill changed after you vetted it. Re-run your full audit!", file=sys.stderr)
                return 2
            if status == "unreachable":
                return 3
            return 0
        out = create_watch(args.url, api_key, webhook_url=args.webhook or "")
        print(f"Watching {args.url}")
        print(f"  watch_id:       {out.get('watch_id')}")
        print(f"  baseline_sha256: {out.get('baseline_sha256')}")
        if args.webhook:
            print(f"  webhook alerts: enabled ({args.webhook.split('/')}...)")
        print("Check anytime: skillsmith watch --check <watch_id>")
        return 0
    except Exception as e126:  # noqa: BLE001 - CLI surface, show server message
        print(f"error: {e126}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    from . import __version__
    parser = argparse.ArgumentParser(prog="skillsmith", description=__doc__)
    parser.add_argument("--version", action="version", version=f"skillsmith {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="scaffold a new skill")
    p_init.add_argument("name", help="skill name, e.g. my-great-skill")
    p_init.add_argument("--path", help="directory to create (default: ./<name>)")
    p_init.add_argument("--description", default="One-line description of what this skill does and when to use it.")
    p_init.add_argument("--python-import", dest="python_import", default=None)
    p_init.set_defaults(func=_cmd_init)

    p_lint = sub.add_parser("lint", help="validate SKILL.md file(s)")
    p_lint.add_argument("path", nargs="?", default=".", help="skill dir or a dir tree to search")
    p_lint.set_defaults(func=_cmd_lint)

    p_list = sub.add_parser("list", help="list skills found under a directory tree")
    p_list.add_argument("path", nargs="?", default=".")
    p_list.set_defaults(func=_cmd_list)

    p_pkg = sub.add_parser("package", help="zip a skill directory for distribution")
    p_pkg.add_argument("path", help="skill directory containing SKILL.md")
    p_pkg.add_argument("--out", help="output zip path")
    p_pkg.set_defaults(func=_cmd_package)

    p_scan = sub.add_parser("scan", help="static security/safety scan of skill(s)")
    p_scan.add_argument("path", nargs="?", default=".", help="skill dir or a dir tree to search")
    p_scan.add_argument("--verbose", action="store_true", help="also print clean skills")
    p_scan.add_argument("--fail-on-high", action="store_true", help="exit 1 if any skill scores 'high' risk")
    p_scan.set_defaults(func=_cmd_scan)

    p_lookup = sub.add_parser("lookup", help="key-less verdict lookup for a skill hash")
    p_lookup.add_argument("--hash", help="SHA-256 hex of the SKILL.md text")
    p_lookup.add_argument("--file", help="local SKILL.md file (hashed automatically)")
    p_lookup.set_defaults(func=_cmd_lookup)

    p_watch = sub.add_parser("watch", help="rug-pull watch for a GitHub-hosted SKILL.md")
    p_watch.add_argument("--url", help="github.com blob or raw URL of the SKILL.md to watch")
    p_watch.add_argument("--check", dest="watch_id", help="existing watch_id to re-check instead of creating")
    p_watch.add_argument("--list", action="store_true", help="list all your watches with their last status")
    p_watch.add_argument("--delete", metavar="WATCH_ID", help="remove a watch you own")
    p_watch.add_argument("--webhook", help="optional Discord/Slack webhook for automatic change alerts")
    p_watch.add_argument("--api-key", default="", help="API key (or set SKILLSMITH_API_KEY)")
    p_watch.set_defaults(func=_cmd_watch)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
