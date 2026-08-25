"""Validation rules for Claude Agent Skill (SKILL.md) files.

A "skill" in the Claude Agent Skills convention is a directory containing a
``SKILL.md`` file with YAML frontmatter (at minimum ``name`` and
``description``) followed by a markdown body that documents how and when the
skill should be used. Skills may optionally point at a Python module via a
``python_import`` frontmatter key, in which case that import should resolve
to an importable module living alongside (or above) the SKILL.md file.

This module implements a small, dependency-light linter for that format so
skill authors get fast, actionable feedback before shipping a skill.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import re
from pathlib import Path
from typing import Any

import yaml

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
REQUIRED_KEYS = ("name", "description")
RECOMMENDED_MAX_DESCRIPTION_CHARS = 500
FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?\n)---\s*\n?(.*)$", re.DOTALL)


class SkillParseError(ValueError):
    """Raised when a SKILL.md file cannot be parsed at all."""


@dataclasses.dataclass
class LintIssue:
    level: str  # "error" | "warning"
    code: str
    message: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"[{self.level}] {self.code}: {self.message}"


@dataclasses.dataclass
class LintResult:
    path: Path
    frontmatter: dict[str, Any] = dataclasses.field(default_factory=dict)
    body: str = ""
    issues: list[LintIssue] = dataclasses.field(default_factory=list)

    @property
    def errors(self) -> list[LintIssue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[LintIssue]:
        return [i for i in self.issues if i.level == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors


def parse_skill_md(text: str) -> tuple[dict[str, Any], str]:
    """Split a SKILL.md file into (frontmatter dict, body markdown)."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        raise SkillParseError(
            "SKILL.md must start with a YAML frontmatter block delimited by '---' lines"
        )
    raw_frontmatter, body = m.group(1), m.group(2)
    try:
        data = yaml.safe_load(raw_frontmatter) or {}
    except yaml.YAMLError as exc:
        raise SkillParseError(f"invalid YAML frontmatter: {exc}") from exc
    if not isinstance(data, dict):
        raise SkillParseError("frontmatter must be a YAML mapping")
    return data, body


def lint_skill_dir(skill_dir: Path) -> LintResult:
    """Lint the SKILL.md inside ``skill_dir`` and return a :class:`LintResult`."""
    skill_dir = Path(skill_dir)
    skill_md = skill_dir / "SKILL.md"
    result = LintResult(path=skill_md)

    if not skill_md.exists():
        result.issues.append(
            LintIssue("error", "missing-skill-md", f"no SKILL.md found in {skill_dir}")
        )
        return result

    # PT-T122 parity: bound input size so a huge SKILL.md cannot exhaust memory/CPU.
    _MAX_SKILL_BYTES = 1_000_000
    if skill_md.stat().st_size > _MAX_SKILL_BYTES:
        result.issues.append(
            LintIssue("error", "skill-md-too-large",
                      f"SKILL.md exceeds {_MAX_SKILL_BYTES} bytes; refusing to scan")
        )
        return result
    text = skill_md.read_text(encoding="utf-8")
    try:
        frontmatter, body = parse_skill_md(text)
    except SkillParseError as exc:
        result.issues.append(LintIssue("error", "unparseable", str(exc)))
        return result

    result.frontmatter = frontmatter
    result.body = body

    for key in REQUIRED_KEYS:
        if not frontmatter.get(key):
            result.issues.append(
                LintIssue("error", "missing-field", f"frontmatter is missing required key '{key}'")
            )

    name = frontmatter.get("name")
    if isinstance(name, str) and not NAME_RE.match(name):
        result.issues.append(
            LintIssue(
                "warning",
                "name-format",
                f"name '{name}' should be lowercase kebab-case, e.g. 'my-great-skill'",
            )
        )

    description = frontmatter.get("description")
    if isinstance(description, str):
        if len(description) > RECOMMENDED_MAX_DESCRIPTION_CHARS:
            result.issues.append(
                LintIssue(
                    "warning",
                    "description-length",
                    f"description is {len(description)} chars; descriptions are loaded into "
                    f"every session's context, keep them under {RECOMMENDED_MAX_DESCRIPTION_CHARS} "
                    "if possible",
                )
            )

    if not body.strip():
        result.issues.append(
            LintIssue(
                "error",
                "empty-body",
                "SKILL.md has no markdown body after the frontmatter; document how/when to use "
                "the skill",
            )
        )

    python_import = frontmatter.get("python_import")
    if python_import:
        if not isinstance(python_import, str):
            result.issues.append(
                LintIssue("error", "python-import-type", "python_import must be a string module name")
            )
        else:
            _check_python_import(python_import, skill_dir, result)

    return result


def _check_python_import(python_import: str, skill_dir: Path, result: LintResult) -> None:
    module_file = skill_dir / f"{python_import}.py"
    package_init = skill_dir / python_import / "__init__.py"
    if module_file.exists() or package_init.exists():
        return
    if importlib.util.find_spec(python_import) is not None:
        return
    result.issues.append(
        LintIssue(
            "warning",
            "python-import-unresolved",
            f"python_import '{python_import}' does not resolve to a module next to SKILL.md "
            "and is not importable in the current environment; make sure it is installed or "
            "shipped alongside the skill",
        )
    )


def find_skill_dirs(root: Path) -> list[Path]:
    """Recursively find every directory under ``root`` containing a SKILL.md."""
    root = Path(root)
    if (root / "SKILL.md").exists():
        return [root]
    return sorted(p.parent for p in root.rglob("SKILL.md"))
