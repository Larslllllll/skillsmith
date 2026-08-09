from pathlib import Path

from skillsmith.scaffold import scaffold_skill
from skillsmith.lint import lint_skill_dir
from skillsmith.package import package_skill


def test_scaffold_creates_valid_skill(tmp_path):
    dest = tmp_path / "cool-skill"
    scaffold_skill(dest, name="cool-skill", description="Does a cool thing when asked.")
    result = lint_skill_dir(dest)
    assert result.ok


def test_scaffold_with_python_import(tmp_path):
    dest = tmp_path / "py-skill"
    scaffold_skill(dest, name="py-skill", description="Wraps a python helper.", python_import="py_skill")
    assert (dest / "py_skill.py").exists()
    result = lint_skill_dir(dest)
    assert not any(i.code == "python-import-unresolved" for i in result.issues)


def test_package_zips_skill(tmp_path):
    dest = tmp_path / "zip-skill"
    scaffold_skill(dest, name="zip-skill", description="Something to zip up.")
    out = package_skill(dest, tmp_path / "zip-skill.zip")
    assert out.exists()
    import zipfile
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
    assert any(n.endswith("SKILL.md") for n in names)
