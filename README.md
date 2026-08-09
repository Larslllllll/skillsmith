# skillsmith

**Author, lint, and package Claude Agent Skills with confidence.**

[![CI](https://github.com/Larslllllll/skillsmith/actions/workflows/ci.yml/badge.svg)](https://github.com/Larslllllll/skillsmith/actions/workflows/ci.yml)
[![PyPI-ready](https://img.shields.io/badge/pypi-ready-blue)](https://pypi.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Claude Agent Skills are just a folder with a `SKILL.md` — a YAML
frontmatter block (`name`, `description`, optionally `python_import`)
followed by markdown instructions that get loaded into an agent's context.
It's a beautifully simple format. It's also very easy to get subtly wrong:
a missing `description`, a `python_import` that doesn't resolve, a
2,000-character description that eats context in every session that loads
it, an empty body that gives the agent no actual guidance.

`skillsmith` is a small, dependency-light CLI and library that catches all
of that **before** an agent ever loads the skill.

```
$ skillsmith lint ./my-skills
OK   web-search (./my-skills/web-search)
WARNING description-length skill-doctor: description is 612 chars; descriptions
        are loaded into every session's context, keep them under 500 if possible
ERROR   missing-field broken-skill: frontmatter is missing required key 'description'
```

## Why this exists

Skills are becoming the primary way agents get new, reusable capabilities —
Anthropic ships them, agent harnesses ship them, and more and more repos
ship their own. There was no small, focused tool to validate the format,
scaffold a new skill correctly on the first try, or package one for
distribution. `skillsmith` is that tool.

## Install

```bash
pip install -e .          # from a clone, until this is published to PyPI
```

## Quickstart

```bash
# Scaffold a new skill with a valid SKILL.md (and an optional python module)
skillsmith init my-great-skill --description "Fetches X and formats it for chat." --python-import my_great_skill

# Validate one skill, or recursively lint every skill in a repo
skillsmith lint ./my-great-skill
skillsmith lint .

# List every skill found under a directory tree, with a one-line summary
skillsmith list .

# Package a skill directory into a distributable .zip
skillsmith package ./my-great-skill --out my-great-skill.zip
```

## What gets checked

| Rule | Level | What it catches |
| --- | --- | --- |
| `missing-skill-md` | error | no `SKILL.md` in the target directory |
| `unparseable` | error | missing/invalid YAML frontmatter block |
| `missing-field` | error | `name` or `description` absent |
| `empty-body` | error | no markdown instructions after the frontmatter |
| `python-import-type` | error | `python_import` isn't a plain string |
| `name-format` | warning | `name` isn't lowercase kebab-case |
| `description-length` | warning | description is unusually long (context-budget smell) |
| `python-import-unresolved` | warning | `python_import` doesn't resolve to a local module or an installed package |

## Library usage

`skillsmith` is also a small, well-tested Python library, so you can wire
skill validation into your own CI or a meta-skill (see
[`examples/skill-doctor`](examples/skill-doctor), a skill that lints every
*other* skill in a repo using `skillsmith` itself):

```python
from skillsmith.lint import find_skill_dirs, lint_skill_dir

for skill_dir in find_skill_dirs("."):
    result = lint_skill_dir(skill_dir)
    if not result.ok:
        raise SystemExit(f"{skill_dir} failed lint: {result.errors}")
```

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

14 tests, no network calls, runs in well under a second.

## License

MIT — see [LICENSE](LICENSE).
