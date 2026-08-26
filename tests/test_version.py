"""Tests for package version metadata -- prevents regression of
the 0.3.0/0.3.1 mismatch that briefly shipped without bumping __version__.
"""
import os
import sys
from pathlib import Path

import pytest

CLI_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CLI_DIR))


def test_pyproject_version_matches_init():
    """pyproject.toml version must match skillsmith/__init__.py __version__."""
    import re
    import skillsmith
    pyproject = (CLI_DIR / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert m, "pyproject.toml missing version field"
    pyproject_ver = m.group(1)
    assert skillsmith.__version__ == pyproject_ver, (
        f"version mismatch: pyproject.toml says {pyproject_ver} but "
        f"skillsmith.__version__ says {skillsmith.__version__}. "
        f"Bump one or the other so they match."
    )


def test_version_is_semver():
    """__version__ must be N.N.N (semver)."""
    import skillsmith
    parts = skillsmith.__version__.split(".")
    assert len(parts) == 3, f"expected N.N.N, got {skillsmith.__version__}"
    for p in parts:
        assert p.isdigit(), f"non-numeric version part: {p}"


def test_cli_version_flag_works():
    """--version prints the package version without crashing."""
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "skillsmith.cli", "--version"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"--version failed: {result.stderr}"
    import skillsmith
    assert skillsmith.__version__ in result.stdout
