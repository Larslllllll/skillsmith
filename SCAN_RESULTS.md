# Live scan results

> **Note:** Results captured 2026-08-09 with engine v0.2.x. Detection coverage has since
> expanded significantly (frontmatter scanning, unicode-obfuscation normalization,
> base64 decoding, credential-URL patterns — see CHANGELOG 0.3.0). Re-run for current numbers.


`skillsmith` isn't just tested against synthetic fixtures — it's been run
against real, in-production skill sets.

## 1. Every skill shipped with Prime Agent (13/13 clean)

```
$ skillsmith lint  /path/to/prime-agent/dist/skills/
$ skillsmith scan  /path/to/prime-agent/dist/skills/ --verbose
```

Result: **13/13 skills pass lint** (valid frontmatter, non-empty body,
resolvable `python_import`) and **13/13 score `clean`** on the security
scan (no shell-out, eval/exec, pickle, credential-reading, or
prompt-injection-style phrasing detected in either the markdown body or the
python source).

| Skill | Lint | Scan |
| --- | --- | --- |
| agent-message | OK | clean |
| agent-observe | OK | clean |
| attach-image | OK | clean |
| compact | OK | clean |
| edit | OK | clean |
| goal | OK | clean |
| linear | OK | clean |
| notion | OK | clean |
| prime-intellect | OK | clean |
| refine | OK | clean |
| rlm-heartbeat | OK | clean |
| skill-creator | OK | clean |
| websearch | OK | clean |

## 2. 2,095 live listings from a production skill marketplace

We also pulled every listing from a live agent-skill marketplace's public
API (2,095 skills, real registered listings, not a fixture) and ran the
description text through the same lint/scan heuristics.

- 0 / 2,095 descriptions exceed the recommended context-budget length
  (max observed: 293 characters; mean: 131).
- 0 / 2,095 descriptions match the prompt-injection or credential-exfiltration
  keyword patterns.

This is the expected, honest result: a marketplace's public *description*
field is short marketing copy, not the place a malicious skill would hide a
payload. The real risk surface is the **executable code** behind a
`python_import` and the **full SKILL.md body**, which most registries don't
expose for scanning until you actually install the skill — which is exactly
why `skillsmith scan` is meant to run locally, right after `pip install` /
`git clone` and before an agent ever loads the skill, not against a
marketplace's summary API.

## Why this exists

Skill/plugin marketplaces for AI agents are growing fast, and most of them
let anyone publish something that another agent's runtime will load into
context and, if it ships code, execute. `skillsmith` turns "eyeball
thousands of community skills one by one" into "run one command, triage
the skills that actually scored risk."
