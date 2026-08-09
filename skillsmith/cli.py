"""Command-line interface for skillsmith."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .lint import find_skill_dirs, lint_skill_dir
from .package import package_skill
from .scaffold import scaffold_skill
from .scan import scan_skill_dir


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skillsmith", description=__doc__)
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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
