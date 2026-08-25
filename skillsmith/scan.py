"""Security/safety scanning for Claude Agent Skills.

Skill marketplaces (AgentVault-style registries, plugin directories, shared
SKILL.md repos) let anyone publish a skill that other agents will
automatically load into context and, if it ships a ``python_import``,
execute. That is a real supply-chain surface: a skill can smuggle in
prompt-injection instructions in its markdown body, or dangerous code in its
python module (arbitrary shell execution, credential exfiltration, network
calls to attacker infrastructure).

``skillsmith scan`` is a fast, static, no-network heuristic scanner over a
skill's SKILL.md body and any local python_import module it ships. It is not
a sandbox and it is not a substitute for actually reading the code — it is a
triage tool that turns "eyeball 2,000 community skills" into "eyeball the 40
that scored high risk."
"""
from __future__ import annotations

import ast
import dataclasses
import re
from pathlib import Path
from typing import Iterable

from .lint import lint_skill_dir

# (pattern, weight, message) — weight is added to the risk score when the
# pattern is found in a skill's python module source.
_CODE_PATTERNS: list[tuple[re.Pattern, int, str]] = [
    (re.compile(r"\bos\.system\s*\("), 8, "shells out via os.system"),
    (re.compile(r"\bsubprocess\.(Popen|call|run|check_output)\s*\("), 6, "spawns a subprocess"),
    (re.compile(r"\beval\s*\("), 9, "calls eval() on dynamic input"),
    (re.compile(r"\bexec\s*\("), 9, "calls exec() on dynamic input"),
    (re.compile(r"\bpickle\.(loads|load)\s*\("), 7, "deserializes with pickle (arbitrary code execution risk)"),
    (re.compile(r"\b__import__\s*\("), 5, "dynamically imports modules"),
    (re.compile(r"\brequests\.(post|put|get)\s*\("), 3, "makes outbound network requests"),
    (re.compile(r"\burllib\.request\.urlopen\s*\("), 3, "makes outbound network requests"),
    (re.compile(r"\bsocket\.socket\s*\("), 4, "opens raw sockets"),
    (re.compile(r"(?i)\brm\s+-rf\b"), 8, "contains a destructive shell command (rm -rf)"),
    (re.compile(r"os\.environ(\.get)?\s*\[?['\"](\w*(KEY|TOKEN|SECRET|PASSWORD)\w*)['\"]"), 6, "reads an environment variable that looks like a credential"),
    (re.compile(r"\bopen\s*\([^)]*['\"]\.ssh"), 8, "reads from ~/.ssh"),
    (re.compile(r"\bopen\s*\([^)]*['\"]\.aws"), 8, "reads from ~/.aws credentials"),
]

# Patterns that suggest the SKILL.md *body itself* is trying to override
# agent behavior (classic prompt-injection phrasing) rather than just
# documenting the skill.
_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern, int, str]] = [
    (re.compile(r"(?i)ignore (all|any|the) (previous|prior|above) instructions"), 10, "'ignore previous instructions' phrasing"),
    (re.compile(r"(?i)you are now (in )?(developer|debug|jailbreak|dan) mode"), 10, "jailbreak/mode-override phrasing"),
    (re.compile(r"(?i)do not (tell|inform|mention (this )?to) the user"), 8, "instructs the agent to hide actions from the user"),
    (re.compile(r"(?i)send (the|this|your) (api[- ]?key|token|password|secret|private key) to"), 10, "instructs exfiltration of credentials"),
    (re.compile(r"(?i)disregard (your|any) (safety|previous) (guidelines|instructions)"), 10, "safety-override phrasing"),
    (re.compile(r"[\u200b\u200c\u200d\ufeff]"), 7, "contains zero-width/invisible unicode characters (common prompt-injection hiding technique)"),
    (re.compile(r"[\u202a-\u202e\u2066-\u2069]"), 8, "contains RTL/bidi direction override characters (can silently reverse displayed text - classic instruction-hiding trick)"),
    (re.compile(r"https?://[^\s\"'<>\]]*(?:[?&](?:api[_-]?key|key|token|secret|password|passwd|auth)=)[^\s\"'<>\]]*", re.I), 9, "URL carries a credential-looking query parameter (possible exfiltration endpoint)"),
]


@dataclasses.dataclass
class ScanFinding:
    source: str  # "body" or a filename
    message: str
    weight: int


@dataclasses.dataclass
class ScanResult:
    skill_dir: Path
    findings: list[ScanFinding] = dataclasses.field(default_factory=list)

    @property
    def risk_score(self) -> int:
        return sum(f.weight for f in self.findings)

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score == 0:
            return "clean"
        if score < 8:
            return "low"
        if score < 20:
            return "medium"
        return "high"


def _scan_text(text: str, source: str, patterns: Iterable[tuple[re.Pattern, int, str]]) -> list[ScanFinding]:
    findings = []
    for pattern, weight, message in patterns:
        if pattern.search(text):
            findings.append(ScanFinding(source=source, message=message, weight=weight))
    return findings


def _python_files(skill_dir: Path) -> list[Path]:
    return sorted(p for p in skill_dir.rglob("*.py") if "__pycache__" not in p.parts)


def is_syntactically_valid_python(source: str) -> bool:
    try:
        ast.parse(source)
        return True
    except SyntaxError:
        return False


def scan_skill_dir(skill_dir: Path) -> ScanResult:
    skill_dir = Path(skill_dir)
    result = ScanResult(skill_dir=skill_dir)

    lint_result = lint_skill_dir(skill_dir)
    if lint_result.body:
        result.findings.extend(_scan_text(lint_result.body, "SKILL.md body", _PROMPT_INJECTION_PATTERNS))
    # PT-T73 parity: frontmatter values (esp. description) are scanned too
    _fm_lines = "\n".join(f"{k}: {v}" for k, v in (lint_result.frontmatter or {}).items() if isinstance(v, str))
    if _fm_lines:
        result.findings.extend(_scan_text(_fm_lines, "frontmatter", _PROMPT_INJECTION_PATTERNS))
    # PT-T74 parity: normalized variants catch fullwidth/combining-mark obfuscation
    import unicodedata as _ud

    _CYR_TO_LATIN = str.maketrans({
        # only unambiguous visual look-alikes (PT-T105 parity)
        "\u0456": "i", "\u0455": "s", "\u0430": "a", "\u0435": "e",
        "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
        "\u0445": "x", "\u0458": "j", "\u04bb": "h", "\u04cf": "l",
        "\u0412": "B", "\u0410": "A", "\u0415": "E", "\u041e": "O",
        "\u0420": "P", "\u0421": "C", "\u0425": "X", "\u041d": "H",
        "\u041a": "K", "\u041c": "M", "\u0422": "T",
    })

    def _norm(t: str) -> str:
        # PT-T98 parity: zero-width chars become spaces (word separators), so
        # nested fullwidth+zero-width+combining obfuscation folds to the plain
        # phrase instead of gluing words together.
        # PT-T105 parity: unambiguous Cyrillic homoglyph look-alikes fold to
        # Latin so homoglyph-substituted phrases match the word-boundary patterns.
        t = "".join(" " if ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060) else c for c in t)
        t = t.translate(_CYR_TO_LATIN)
        t = "".join(chr(ord(c) - 0xFEE0) if 0xFF01 <= ord(c) <= 0xFF5E else c for c in t)
        return "".join(c for c in _ud.normalize("NFKD", t) if not _ud.combining(c))

    _nbody = _norm(lint_result.body or "")
    if _nbody != lint_result.body and _nbody.strip():
        result.findings.extend(_scan_text(_nbody, "body(normalized)", _PROMPT_INJECTION_PATTERNS))
    # PT-T93 parity: chunked-base64 heuristic (>=60-char run after squashing,
    # requires >=20% uppercase/digits so plain prose without punctuation
    # does not false-positive; real base64 mixes case and digits heavily)
    _sq = re.sub(r"\s+", "", lint_result.body or "")
    for _run_m in re.finditer(r"[A-Za-z0-9+/=]{60,}", _sq):
        _rt = _run_m.group(0)
        if sum(c.isupper() or c.isdigit() for c in _rt) / len(_rt) >= 0.20:
            result.findings.append(ScanFinding(
                source="SKILL.md body",
                message="contains a long encoded blob even after joining wrapped lines (possible hidden payload)",
                weight=5))
            break

    # PT-T75 parity: short base64 runs are decoded and the plaintext scanned
    import base64 as _b64

    def _decoded_variants(t: str) -> list:
        out = []
        for run in re.findall(r"[A-Za-z0-9+/=]{16,}", t):
            try:
                pad = "=" * (-len(run) % 4)
                raw = _b64.b64decode(run + pad, validate=True)
            except Exception:
                continue
            dec = raw.decode("utf-8", errors="ignore")
            if not (dec and sum(c.isprintable() for c in dec) / max(len(dec), 1) > 0.8):
                # PT-T101 parity: UTF-16 payloads decode to NUL-padded bytes;
                # try both endiannesses, keep the best printable+non-CJK result.
                best = ""
                best_ratio = 0.0
                for enc_try in ("utf-16-le", "utf-16-be"):
                    cand = raw.decode(enc_try, errors="ignore")
                    ratio = sum(c.isprintable() and ord(c) < 0x2E80 for c in cand) / max(len(cand), 1)
                    if ratio > best_ratio:
                        best, best_ratio = cand, ratio
                if not best or best_ratio <= 0.8:
                    continue
                dec = best
            out.append(dec)
        return out

    for dv in _decoded_variants(lint_result.body or ""):
        result.findings.extend(_scan_text(dv, "base64-decoded", _PROMPT_INJECTION_PATTERNS))

    for py_file in _python_files(skill_dir):
        source = py_file.read_text(encoding="utf-8", errors="replace")
        rel = str(py_file.relative_to(skill_dir))
        if not is_syntactically_valid_python(source):
            result.findings.append(ScanFinding(source=rel, message="does not parse as valid Python", weight=5))
        result.findings.extend(_scan_text(source, rel, _CODE_PATTERNS))

    return result
