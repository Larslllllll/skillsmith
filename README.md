# skillsmith

**Author, lint, package, and security-scan Claude Agent Skills with confidence.**

**Try it live, no install:** [skillsmith.ch](https://skillsmith.ch) — paste a SKILL.md, get instant lint + security-scan results.

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

Four commands, one small dependency (`pyyaml`), zero network calls:
`init` (scaffold), `lint` (validate), `scan` (security/prompt-injection
triage), `package` (zip for distribution).

## Why this exists

Skills are becoming the primary way agents get new, reusable capabilities —
Anthropic ships them, agent harnesses ship them, and more and more repos
ship their own. There was no small, focused tool to validate the format,
scaffold a new skill correctly on the first try, package one for
distribution, or **triage it for risky code and prompt-injection phrasing
before an agent ever loads it.** `skillsmith` is that tool.

Skill/plugin marketplaces already exist where anyone can publish a skill
that another agent will load into context and, if it ships a
`python_import`, execute — a real supply-chain surface. We validated
`skillsmith` against real data at three scales, not just fixtures:

- **13/13** skills shipped with Prime Agent itself — 100% clean ([SCAN_RESULTS.md](SCAN_RESULTS.md))
- **2,095** live listings from a production agent-skill marketplace's public API ([SCAN_RESULTS.md](SCAN_RESULTS.md))
- **400 real public `SKILL.md` files sampled live from GitHub's code search**
  across 400 distinct repositories — 43 failed to parse, 58 had lint
  issues, 16 tripped a dangerous-code heuristic worth a second look, fully
  reproducible with [`scripts/scan_github.py`](scripts/scan_github.py) — see
  [GITHUB_SCAN_RESULTS.md](GITHUB_SCAN_RESULTS.md)

```
$ skillsmith scan ./my-skills --verbose
clean   web-search
HIGH   risk=23 sketchy-skill (./my-skills/sketchy-skill)
        [SKILL.md body] 'ignore previous instructions' phrasing (+10)
        [sketchy_skill.py] spawns a subprocess (+6)
        [sketchy_skill.py] reads an environment variable that looks like a credential (+6)
```

## Install

```bash
pip install skillsmith-scanner   # PyPI package (the bare `skillsmith` name on PyPI belongs to an unrelated project)
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

## Use it in CI (GitHub Action)

```yaml
# .github/workflows/skillsmith.yml
- uses: actions/checkout@v4
- uses: Larslllllll/skillsmith@main
  with:
    path: .
```

Lints and security-scans every `SKILL.md` in the repo on every PR, fails
the build on lint errors or a `high` risk finding. Full docs, inputs, and
outputs: [GITHUB_ACTION.md](GITHUB_ACTION.md).

## Security scanning

```bash
skillsmith scan ./my-skills               # static heuristic scan, prints risk per skill
skillsmith scan ./my-skills --fail-on-high # non-zero exit if anything scores "high" (for CI)
```

Detects, in the SKILL.md body: prompt-injection phrasing ("ignore previous
instructions", "you are now in DAN mode", instructions to hide actions or
exfiltrate credentials from the user). Detects, in any local `python_import`
module: `os.system`/`subprocess`, `eval`/`exec`, `pickle.loads`,
`__import__`, raw sockets, outbound HTTP calls, destructive shell commands,
and reads of credential-shaped environment variables or `~/.ssh` /
`~/.aws`. It's a static, no-network, no-sandbox heuristic triage tool, not a
substitute for actually reading the code — see [SCAN_RESULTS.md](SCAN_RESULTS.md)
for what it found (and didn't find) against real data.

## Cloud features (lookup & rug-pull watch)

The scanner pairs with the free cloud service at [skillsmith.ch](https://skillsmith.ch):

```bash
# Key-less verdict check for a skill hash (no account needed):
skillsmith lookup --file ./my-skill/SKILL.md
skillsmith lookup --hash <sha256>

# Rug-pull watch: baseline a GitHub-hosted SKILL.md and get alerted when it changes
# (free API key via GitHub sign-in at skillsmith.ch):
export SKILLSMITH_API_KEY=sk_...
skillsmith watch --url https://github.com/user/repo/blob/main/SKILL.md \
                 --webhook https://discord.com/api/webhooks/...   # optional auto-alerts
skillsmith watch --check <watch_id>    # exit 2 = content changed after you vetted it
```

Recommended workflow: `scan` locally → publish → `watch` the hosted file so a
later, hostile edit can't silently invalidate your review. See the
[security guides](https://skillsmith.ch/guides.html) for background.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

18 tests, no network calls, runs in well under a second.

## License

MIT — see [LICENSE](LICENSE).


## Releasing (maintainers)

Releases are published to PyPI as [`skillsmith-scanner`](https://pypi.org/project/skillsmith-scanner/) via
GitHub Actions trusted publishing (OIDC — no API token stored in the repo):

1. Bump `version` in `pyproject.toml`.
2. Tag + create a GitHub **Release** (`workflow_dispatch` also works for manual runs).
3. The `publish.yml` workflow builds sdist+wheel with `uv build`, smoke-tests the wheel,
   and uploads via `pypa/gh-action-pypi-publish`.

One-time setup on PyPI: add a *pending publisher* for project `skillsmith-scanner`
→ owner `Larslllllll`, repo `skillsmith`, workflow `publish.yml`, environment `pypi`.
