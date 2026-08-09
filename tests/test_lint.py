from pathlib import Path

import pytest

from skillsmith.lint import SkillParseError, lint_skill_dir, parse_skill_md, find_skill_dirs


GOOD_SKILL = """---
name: my-great-skill
description: Does one thing well and says exactly when to use it.
---

# My Great Skill

Use this when the user asks for X. Call `do_thing()`.
"""

MISSING_DESC = """---
name: my-great-skill
---

Body text.
"""

NO_FRONTMATTER = "# Just a heading\n\nNo frontmatter here.\n"


def write_skill(dir_path: Path, text: str) -> Path:
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / "SKILL.md").write_text(text, encoding="utf-8")
    return dir_path


def test_parse_skill_md_ok():
    fm, body = parse_skill_md(GOOD_SKILL)
    assert fm["name"] == "my-great-skill"
    assert "Use this when" in body


def test_parse_skill_md_requires_frontmatter():
    with pytest.raises(SkillParseError):
        parse_skill_md(NO_FRONTMATTER)


def test_lint_good_skill_has_no_errors(tmp_path):
    d = write_skill(tmp_path / "a-skill", GOOD_SKILL)
    result = lint_skill_dir(d)
    assert result.ok
    assert result.errors == []


def test_lint_missing_description_is_error(tmp_path):
    d = write_skill(tmp_path / "a-skill", MISSING_DESC)
    result = lint_skill_dir(d)
    assert not result.ok
    codes = {i.code for i in result.errors}
    assert "missing-field" in codes


def test_lint_missing_skill_md(tmp_path):
    result = lint_skill_dir(tmp_path)
    assert not result.ok
    assert result.errors[0].code == "missing-skill-md"


def test_lint_bad_name_format_is_warning(tmp_path):
    text = GOOD_SKILL.replace("my-great-skill", "MyGreatSkill")
    d = write_skill(tmp_path / "a-skill", text)
    result = lint_skill_dir(d)
    assert result.ok  # warning only, not an error
    assert any(i.code == "name-format" for i in result.warnings)


def test_lint_long_description_is_warning(tmp_path):
    text = GOOD_SKILL.replace(
        "description: Does one thing well and says exactly when to use it.",
        "description: " + ("x" * 600),
    )
    d = write_skill(tmp_path / "a-skill", text)
    result = lint_skill_dir(d)
    assert any(i.code == "description-length" for i in result.warnings)


def test_lint_empty_body_is_error(tmp_path):
    text = "---\nname: my-great-skill\ndescription: does a thing.\n---\n\n   \n"
    d = write_skill(tmp_path / "a-skill", text)
    result = lint_skill_dir(d)
    assert any(i.code == "empty-body" for i in result.errors)


def test_lint_unresolved_python_import_is_warning(tmp_path):
    text = GOOD_SKILL.replace(
        "description: Does one thing well and says exactly when to use it.",
        "description: does a thing.\npython_import: totally_not_a_real_module_xyz",
    )
    d = write_skill(tmp_path / "a-skill", text)
    result = lint_skill_dir(d)
    assert any(i.code == "python-import-unresolved" for i in result.warnings)


def test_lint_resolved_local_python_import(tmp_path):
    text = GOOD_SKILL.replace(
        "description: Does one thing well and says exactly when to use it.",
        "description: does a thing.\npython_import: helper",
    )
    d = write_skill(tmp_path / "a-skill", text)
    (d / "helper.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    result = lint_skill_dir(d)
    assert not any(i.code == "python-import-unresolved" for i in result.issues)


def test_find_skill_dirs(tmp_path):
    write_skill(tmp_path / "one", GOOD_SKILL)
    write_skill(tmp_path / "nested" / "two", GOOD_SKILL)
    found = find_skill_dirs(tmp_path)
    assert len(found) == 2
