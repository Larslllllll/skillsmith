"""Package a skill directory into a distributable zip archive."""
from __future__ import annotations

import zipfile
from pathlib import Path

DEFAULT_EXCLUDES = {"__pycache__", ".pytest_cache", ".git", ".DS_Store"}


def package_skill(skill_dir: Path, out_path: Path | None = None) -> Path:
    skill_dir = Path(skill_dir)
    if not (skill_dir / "SKILL.md").exists():
        raise FileNotFoundError(f"{skill_dir} has no SKILL.md; nothing to package")

    out_path = Path(out_path) if out_path else skill_dir.with_suffix(".zip")
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(skill_dir.rglob("*")):
            if path.is_dir():
                continue
            if any(part in DEFAULT_EXCLUDES for part in path.parts):
                continue
            arcname = Path(skill_dir.name) / path.relative_to(skill_dir)
            zf.write(path, arcname)
    return out_path
