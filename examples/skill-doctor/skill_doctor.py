"""skill-doctor: lint every SKILL.md under a directory tree using skillsmith."""
from __future__ import annotations

import sys
from pathlib import Path

from skillsmith.lint import find_skill_dirs, lint_skill_dir


def run(root: str = ".") -> int:
    """Lint every skill under ``root``; return process-style exit code."""
    root_path = Path(root)
    skill_dirs = find_skill_dirs(root_path)
    if not skill_dirs:
        print(f"No SKILL.md files found under {root_path}")
        return 0

    exit_code = 0
    for skill_dir in skill_dirs:
        result = lint_skill_dir(skill_dir)
        label = result.frontmatter.get("name", skill_dir)
        for issue in result.issues:
            print(f"{issue.level.upper():7} {label}: {issue.message}")
        if not result.ok:
            exit_code = 1
        else:
            print(f"OK      {label}")
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else "."))
