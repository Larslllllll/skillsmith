# Changelog

## 0.3.0 (2026-08-26)

Engine hardening release (web + CLI parity):

- Unicode evasion detection: zero-width characters, RTL/bidi overrides,
  fullwidth folding and combining-mark stripping (normalized variants are
  scanned in addition to the raw text); stacked combinations of these
  techniques (e.g. fullwidth + zero-width + combining) fold to the plain
  phrase and are detected
- Frontmatter values (name/description block) are now scanned for prompt
  injection and paraphrase patterns - previously only the body was checked
- Short base64 runs (>= 16 chars) are decoded (validated) and the decoded
  text is scanned; findings are reported with source "base64-decoded"
- New pattern: URLs carrying credential-looking query parameters
  (api_key/key/token/secret/password/auth=)
- Chunked-base64 heuristic: long encoded runs (>60 chars) hidden across
  wrapped lines are flagged; plain prose without punctuation is excluded
  (>=20% uppercase/digits required)
- UTF-16 base64 payloads: NUL-padded decodes are retried as UTF-16LE/BE and
  the best printable result is scanned
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
