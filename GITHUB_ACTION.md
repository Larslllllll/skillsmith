# Using skillsmith as a GitHub Action

Add this to any repo that ships Claude Agent Skills (`SKILL.md` files) to
lint and security-scan them automatically on every PR:

```yaml
# .github/workflows/skillsmith.yml
name: skillsmith

on:
  pull_request:
    paths:
      - "**/SKILL.md"
  push:
    branches: [main]
    paths:
      - "**/SKILL.md"

jobs:
  skillsmith:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Larslllllll/skillsmith@main
        with:
          path: .
```

That's it. The action:

1. Installs `skillsmith` (from this repo, pinned to whatever ref you set —
   `@main`, a tag like `@v0.2.0`, or a commit SHA).
2. Runs `skillsmith lint <path>` — fails the job if any `SKILL.md` is
   missing required frontmatter fields, has an empty body, etc.
3. Runs `skillsmith scan <path> --fail-on-high` — fails the job if any
   skill's body or `python_import` module scores `high` risk (dangerous
   code patterns, prompt-injection phrasing).

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Directory to search for `SKILL.md` files, recursively. |
| `fail-on-lint-errors` | `true` | Fail the job on lint errors. |
| `fail-on-high-risk` | `true` | Fail the job on a `high` risk security finding. |
| `skillsmith-version` | (latest `main`) | Pin to a specific tag/ref instead of `main`. |

## Outputs

| Output | Values |
| --- | --- |
| `lint-result` | `pass` / `fail` |
| `scan-result` | `pass` / `fail` |

## Why put this in CI instead of only the live web demo

The [live scanner](https://skillsmith-web.vercel.app) is great for a
one-off check before you install someone else's skill. A CI action is for
the other direction: catching a regression (a new `SKILL.md` you're about
to merge that fails lint, or accidentally includes something that trips
the security heuristics) before it ships, automatically, on every PR —
no one has to remember to paste it into the web tool.
