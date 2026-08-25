# Changelog

## 0.3.0 (2026-08-24)

Engine hardening release (web + CLI parity):

- Unicode evasion detection: zero-width characters, RTL/bidi overrides,
  fullwidth folding and combining-mark stripping (normalized variants are
  scanned in addition to the raw text)
- Frontmatter values (name/description block) are now scanned for prompt
  injection and paraphrase patterns - previously only the body was checked
- Short base64 runs (>= 16 chars) are decoded (validated) and the decoded
  text is scanned; findings are reported with source "base64-decoded"
- New pattern: URLs carrying credential-looking query parameters
  (api_key/key/token/secret/password/auth=)
- OSV package names are capped at 214 chars (versions at 20) to prevent
  oversized upstream requests
- YAML frontmatter errors surface as a clean validation error instead of
  crashing (safe_load rejects object tags; no deserialization risk)

## 0.2.0

- Watch mode: create/check/list/delete watches against skillsmith.ch,
  optional Discord/Slack webhooks, rug-pull hash comparison
- GitHub Action integration, badge generation

## 0.1.0

- Initial public release: static heuristic scan of SKILL.md files
  (prompt injection, exfiltration, dangerous code, homoglyphs), OSV
  dependency enrichment, lookup/registry access
