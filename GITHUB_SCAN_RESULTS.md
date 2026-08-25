# GitHub-scale scan results

> **Note:** Results captured 2026-08-09 with engine v0.2.x. Detection coverage has since
> expanded significantly (frontmatter scanning, unicode-obfuscation normalization,
> base64 decoding, credential-URL patterns — see CHANGELOG 0.3.0). Re-run for current numbers.


To sanity-check `skillsmith` against the messiest possible input — real
files, written by real people, with no fixture cleanliness — we ran it
against **400 real, public `SKILL.md` files sampled live from GitHub's code
search** (400 distinct repositories, not 400 files from one repo). Fully
reproducible with [`scripts/scan_github.py`](scripts/scan_github.py):

```bash
GH_TOKEN=ghp_... python scripts/scan_github.py --sample-size 400
```

## Headline numbers

GitHub's own filename search reports **4,915,200** results for
`filename:SKILL.md` (a large over-count that includes unrelated files that
happen to share the name — code search matches loosely). Of the first 400
*distinct-repository* hits we could download and parse:

| Check | Count | % |
| --- | --- | --- |
| Files analyzed | 400 | 100% |
| Failed to parse as valid frontmatter + body | 43 | 10.75% |
| Lint issues (missing required fields / empty body) | 58 | 14.5% |
| Prompt-injection heuristic matches | 0 | 0% |
| Dangerous-code heuristic matches (in embedded code blocks) | 16 | 4% |

## What "dangerous-code heuristic matches" actually means here

These are **not** all malicious — most are legitimate ops/devops skills
whose documentation *itself* includes an `rm -rf`, a `subprocess` call, or a
credential-shaped env var, because that's what the skill is for (e.g. a
"clean up a workspace" skill). That's exactly the point: `skillsmith scan`
is a **triage** tool. It turns "read 400 files by hand" into "read the 16
that actually mention something worth a second look", for example:

- [`Free-The-Ai/free-ai/blob/065b12c56a1e5911364aa973a5ab83b6ad1...`](https://github.com/Free-The-Ai/free-ai/blob/065b12c56a1e5911364aa973a5ab83b6ad114047/SKILL.md) — reads an environment variable that looks like a credential
- [`Dicklesworthstone/cass_memory_system/blob/89977c582a8cb17b19...`](https://github.com/Dicklesworthstone/cass_memory_system/blob/89977c582a8cb17b190af2b039fb844e665237be/SKILL.md) — contains a destructive shell command (rm -rf)
- [`dman1313/hermes-brain/blob/e24bdb12dc35dc5c52255754ff7c54b88...`](https://github.com/dman1313/hermes-brain/blob/e24bdb12dc35dc5c52255754ff7c54b8859cbee8/profiles/dream/skills/devops/hermes-workspace-setup/SKILL.md) — contains a destructive shell command (rm -rf)
- [`middle-chunjie/mywiki/blob/a43962d7558b6f2637f97419be07777c6...`](https://github.com/middle-chunjie/mywiki/blob/a43962d7558b6f2637f97419be07777c60d14db6/.aris/skill-sync/rendered/20260518_173322_277047/dse-loop/SKILL.md) — contains a destructive shell command (rm -rf)
- [`benchflow-ai/skillsbench-trajectories/blob/37484902dabffa24e...`](https://github.com/benchflow-ai/skillsbench-trajectories/blob/37484902dabffa24e91fac710ddcb90395fc5114/xiangyi-jobs/main-with-skills-pass1/find-topk-similiar-chemicals__Yr69ojj/agent/sessions/skills/pubchem-database/SKILL.md) — makes outbound network requests
- [`phoroth/AGENTIC/blob/29cd62e80278eeac7dc39bd3716437cc25ecdc5...`](https://github.com/phoroth/AGENTIC/blob/29cd62e80278eeac7dc39bd3716437cc25ecdc51/plugins/ecc/docs/es/skills/python-patterns/SKILL.md) — makes outbound network requests
- [`voxelepic/rat-portfolio/blob/430e8bf27853937a997ed04ff9062a4...`](https://github.com/voxelepic/rat-portfolio/blob/430e8bf27853937a997ed04ff9062a48bfef26e9/.agent/skills/audio-transcriber/SKILL.md) — spawns a subprocess
- [`TimLai666/installed-skills/blob/c23df53bf5f6cef27bcf87dcb11f...`](https://github.com/TimLai666/installed-skills/blob/c23df53bf5f6cef27bcf87dcb11f7c66be0e6d10/scientific-skills_K-Dense-AI/protocolsio-integration/SKILL.md) — makes outbound network requests
- [`FlyFireF/PersonalAgentAPP/blob/355ca73dd3822f3683a9420df0543...`](https://github.com/FlyFireF/PersonalAgentAPP/blob/355ca73dd3822f3683a9420df054356c713b79a8/growth-companion/skills/research/research-paper-writing/SKILL.md) — makes outbound network requests
- [`David-Li0406/meta-skill-evloving/blob/ca3a335628981df10c36e0...`](https://github.com/David-Li0406/meta-skill-evloving/blob/ca3a335628981df10c36e00cb9850df2c247ab9a/skill-flow/data/skills-refined-agentskillos-36k/skillsmp/zoom-1/SKILL.md) — dynamically imports modules, makes outbound network requests
- [`akillness/jeo-skills/blob/052828847772f185093c5788e61d812f3b...`](https://github.com/akillness/jeo-skills/blob/052828847772f185093c5788e61d812f3b83c77a/.agent-skills/codeflow/SKILL.md) — calls eval() on dynamic input
- [`x402agent/SolanaOS/blob/37041b5d74e4da89b4f23b68858895391154...`](https://github.com/x402agent/SolanaOS/blob/37041b5d74e4da89b4f23b688588953911547651/.agents/skills/honcho-integration/SKILL.md) — reads an environment variable that looks like a credential
- [`gchittora/Pulsetrack/blob/8f2f37fe4377cb9efeff586c8c2b077852...`](https://github.com/gchittora/Pulsetrack/blob/8f2f37fe4377cb9efeff586c8c2b077852040d38/.agent/skills/audio-transcriber/SKILL.md) — spawns a subprocess
- [`kaikunay/psyprofiler-io/blob/4ce453d50dbf7ab9f0dd70c901691ee...`](https://github.com/kaikunay/psyprofiler-io/blob/4ce453d50dbf7ab9f0dd70c901691ee90bc439bb/.agent/skills/audio-transcriber/SKILL.md) — spawns a subprocess
- [`wAyNecheRui/uhuru-safi-mradi/blob/794620490997418a9a297c6b86...`](https://github.com/wAyNecheRui/uhuru-safi-mradi/blob/794620490997418a9a297c6b860e7f86484f7e71/.agent/skills/audio-transcriber/SKILL.md) — spawns a subprocess
- [`GalacticVraj/Vraj-Portfolio/blob/2b6f17d71f4c81580db214b02cb...`](https://github.com/GalacticVraj/Vraj-Portfolio/blob/2b6f17d71f4c81580db214b02cbe5b213673e3b1/.agent/skills/audio-transcriber/SKILL.md) — spawns a subprocess

Zero of the 400 matched the prompt-injection heuristics (no "ignore
previous instructions" / hidden-exfiltration phrasing found in this real
sample) — reassuring, and also expected, since blatant injection attempts
are rare in skills written by their own authors for their own use. The
value of the check is catching the rare one that isn't.

## What "failed to parse" means

10.75% of files matching `filename:SKILL.md` on GitHub are not actually
Claude Agent Skill files at all — sysadmin cheat sheets, game design docs,
training notes for unrelated "skill" concepts (e.g. interpersonal skills
training material) that happen to be named `SKILL.md` or `skill.md`. This
is real-world noise skillsmith has to survive, and does: it fails closed
(reports a parse error) rather than silently misinterpreting non-skill
content as a valid skill.

## Reproduce it yourself

```bash
pip install -e ".[dev]"
GH_TOKEN=$(gh auth token) python scripts/scan_github.py --sample-size 400
```

Raw results for the run documented above: [`github_scan_raw_results.json`](github_scan_raw_results.json).
