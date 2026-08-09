---
name: skill-doctor
description: Lints every Claude Agent Skill (SKILL.md) in a repo before you ship it. Use this whenever you add or edit a skill, to catch missing frontmatter fields, oversized descriptions, or a broken python_import before an agent ever loads it.
python_import: skill_doctor
---

# Skill Doctor

A meta-skill: it uses `skillsmith` to lint every other skill in this
repository, so an agent (or a CI job) can self-check the skills it ships
before anyone relies on them.

## Usage

```
python -c "from skill_doctor import run; run('.')"
```

or from the shell:

```
skillsmith lint .
```

## When to use this

- Right after scaffolding a new skill with `skillsmith init`.
- In CI, before merging a PR that adds or edits a `SKILL.md`.
- Whenever an agent is about to hand a freshly written skill to another agent.
