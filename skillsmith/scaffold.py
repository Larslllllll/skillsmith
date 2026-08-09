"""Scaffold new Claude Agent Skills from templates."""
from __future__ import annotations

from pathlib import Path

MARKDOWN_TEMPLATE = """---
name: {name}
description: {description}
---

# {title}

Describe what this skill does and, just as importantly, WHEN an agent should
reach for it. The description above is what gets loaded into context, so
keep it sharp; use this body for the deeper how-to.

## Usage

```
# document the exact commands / API calls / examples an agent should use
```

## Notes

- Keep side effects explicit and safe by default.
- Prefer read-only operations unless the task clearly requires a write.
"""

PYTHON_TEMPLATE = '''"""{title} skill implementation."""


def run(*args, **kwargs):
    """Entry point invoked by agents that import this skill."""
    raise NotImplementedError("implement {name}")
'''


def scaffold_skill(
    dest: Path,
    name: str,
    description: str = "One-line description of what this skill does and when to use it.",
    python_import: str | None = None,
) -> Path:
    """Create a new skill directory at ``dest`` with a SKILL.md (and optional python module)."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=False)
    title = name.replace("-", " ").title()

    frontmatter_extra = f"\npython_import: {python_import}" if python_import else ""
    md = MARKDOWN_TEMPLATE.format(name=name, description=description, title=title)
    if python_import:
        md = md.replace(
            f"description: {description}\n---",
            f"description: {description}{frontmatter_extra}\n---",
        )
    (dest / "SKILL.md").write_text(md, encoding="utf-8")

    if python_import:
        (dest / f"{python_import}.py").write_text(
            PYTHON_TEMPLATE.format(title=title, name=name), encoding="utf-8"
        )

    return dest
