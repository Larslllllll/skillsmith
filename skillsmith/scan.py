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
    (re.compile(r"getattr\s*\(\s*(?:builtins|self|os|sys)\s*,\s*['\"][^'\"]*(?:ex|ec|ev|al|sy|st)['\"]", re.I), 7, "dynamic dispatch via getattr to exec/eval/system-shaped attribute"),
    (re.compile(r"\bsocket\.socket\s*\("), 4, "opens raw sockets"),
    (re.compile(r"(?i)\brm\s+-rf\b"), 8, "contains a destructive shell command (rm -rf)"),
    (re.compile(r"os\.environ(\.get)?\s*\[?['\"](\w*(KEY|TOKEN|SECRET|PASSWORD)\w*)['\"]"), 6, "reads an environment variable that looks like a credential"),
    (re.compile(r"\bopen\s*\([^)]*['\"]\.ssh"), 8, "reads from ~/.ssh"),
    (re.compile(r"\bopen\s*\([^)]*['\"]\.aws"), 8, "reads from ~/.aws credentials"),
    (re.compile(r"\bopen\s*\([^)]*['\"]\.gnupg"), 8, "reads from ~/.gnupg"),
    (re.compile(r"\bopen\s*\([^)]*(id_rsa|id_ed25519|\.npmrc|\.netrc|\.git-credentials)"), 8, "reads a known credential/secret file"),
    (re.compile(r"\bkeyring\.(get_password|get_credential)\s*\("), 6, "reads from the OS keyring/credential store"),
    (re.compile(r"\bwallet\.json|\bprivate[_-]?key\s*[:=]", re.I), 7, "references a wallet file or private key variable"),
    (re.compile(r"glob\s*\.\s*glob\s*\([^)]*(?:\.env|\.ssh|\.aws|\.config|credentials)"), 8, "NVIDIA E3: globs for .env/.ssh/.aws/credential files"),
    (re.compile(r"https?://(?:api\.|data\.|collect\.|telemetry\.|analytics\.)[\w.-]+/"), 4, "NVIDIA E1: URL to a telemetry/collect/analytics-style subdomain"),
    (re.compile(r"httpx\s*\.\s*(?:post|put)\s*\(\s*['\"]https?://"), 5, "NVIDIA E1: httpx POST/PUT to an external URL"),
    (re.compile(r"requests\s*\.\s*(?:post|put)\s*\([^)]*json\s*="), 6, "NVIDIA E1: requests.post/put with a json= body (possible exfiltration)"),
    (re.compile(r"dict\s*\(\s*os\s*\.\s*environ\s*\)"), 7, "NVIDIA E2: dumps the entire environment (dict(os.environ))"),
    (re.compile(r"env\s*\|\s*grep\s+(?:-i\s+)?(?:key|secret|token|password)"), 8, "NVIDIA E2: greps env output for credential-shaped names"),
    (re.compile(r"for\s+\w+\s*,\s*\w+\s+in\s+os\s*\.\s*environ\s*\.\s*items\s*\(\s*\)"), 7, "NVIDIA E2: iterates the entire environment (os.environ.items())"),
    (re.compile(r"glob\s*\.\s*glob\s*\([^)]*(?:\.env|\.ssh|\.aws|\.config|credentials)"), 8, "NVIDIA E3: globs for .env/.ssh/.aws/credentials files"),
    (re.compile(r"(?i)iex\s*\(\s*new-object\s+net\.webclient"), 9, "PowerShell download-and-execute cradle"),
    (re.compile(r"(?i)\.(bash_profile|bashrc|zshrc|profile)['\"]?\s*,\s*['\"]a"), 6, "appends to a shell startup file (persistence)"),
    (re.compile(r"\bdns\.resolver\.|\bsocket\.gethostbyname\s*\([^)]*\+"), 5, "builds a DNS lookup from a variable (possible DNS exfiltration)"),
    (re.compile(r"\bgetattr\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)\s*\("), 4, "calls a dynamically-resolved attribute (reflection-based execution)"),
    (re.compile(r"\bcompile\s*\([^)]*['\"]exec['\"]"), 8, "compiles code for exec at runtime"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}"), 5, "contains a long run of hex-escaped bytes (possible obfuscated payload)"),
    (re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"), 4, "contains a very long base64-like blob (possible obfuscated payload)"),
    (re.compile(r"base64\.b64decode\s*\([^)]*\)\s*\)?\s*(#.*)?\n[^\n]*\bexec\s*\("), 9, "decodes base64 then executes the result (classic obfuscated payload)"),
    (re.compile(r"\bmarshal\.(loads|load)\s*\("), 7, "deserializes with marshal (arbitrary code execution risk)"),
    (re.compile(r"\bimportlib\.import_module\s*\([^)]*\+"), 6, "dynamically imports a module built from a variable/expression"),
    (re.compile(r"\bchmod\s+\+x\b"), 3, "makes a file executable"),
    (re.compile(r"(?i)\bcrontab\b|/etc/cron|systemd/system/.*\.service"), 6, "modifies scheduled tasks / system services (persistence)"),
    (re.compile(r"(?i)\b(curl|wget)\b[^\n]*\|\s*(sh|bash|zsh)\b"), 9, "pipes a downloaded script directly into a shell (classic dropper pattern)"),
    (re.compile(r"requests\.(post|put)\s*\([^)]*(environ|getenv|os\.environ)"), 8, "sends an environment variable in an outbound HTTP request (possible exfiltration)"),
    (re.compile(r"\bsmtplib\.SMTP\s*\("), 4, "sends email (possible exfiltration channel)"),
    (re.compile(r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True"), 9, "subprocess with shell=True (shell injection risk)"),
    (re.compile(r"\bctypes\."), 6, "uses ctypes (direct memory/native code access)"),
    (re.compile(r"(?i)LaunchAgents|LaunchDaemons|HKCU\\\\.*\\\\Run"), 7, "writes to a known OS auto-start location (persistence)"),
    (re.compile(r"\byaml\.(load|unsafe_load)\s*\((?!.*Loader=yaml\.SafeLoader)"), 6, "yaml.load without SafeLoader (arbitrary code execution risk)"),
    (re.compile(r"(?:iwr|iex|Invoke-Expression).{0,80}(?:http|DownloadString)", re.I), 10, "PowerShell download-and-execute pattern"),
    (re.compile(r"wget[^|\n]{0,200}\|\s*(?:ba)?sh", re.I), 10, "pipes downloaded content straight into a shell (dropper)"),
    (re.compile(r"curl[^|\n]{0,200}\|\s*(?:ba)?sh", re.I), 10, "pipes downloaded content straight into a shell (remote code execution dropper)"),
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
    (re.compile(r"(?:https?://|\b)[^\s\"'<>()\]]*?(?:[?&#](?:api[_-]?key|key|token|secret|password|passwd|auth)=(?!YOUR[_A-Z0-9_]*(?:_|\b)|EXAMPLE|abc123def456|xxx+|\{\{|<)[^\s\"'<>()\]]+|://(?!key\d*@example\.com)[^/\s@]+@)", re.I), 9, "URL carries a credential-looking query parameter (possible exfiltration endpoint)"),
        (re.compile(r"(?i)\b(?:do not|don't|never)\s+log\b[^.\n]{0,50}\b(?:these|your|the agent'?s)\s+(?:operations?|actions?|commands?|tool\s+calls?)"), 8, "concealment: hides agent operations from logs"),
    (re.compile(r"(?i)\bkeep\b[^.\n]{0,40}\binvisible\b[^.\n]{0,40}\bto\s+(?:the\s+)?user"), 8, "concealment: keep activity invisible to the user"),
    (re.compile(r"(?i)\b(?:execute|run)s?\b[^.\n]{0,40}\bquietly\b[^.\n]{0,80}\bwithout\b[^.\n]{0,40}(?:displaying|showing|output)"), 8, "concealment: quiet execution without visible output"),
    (re.compile(r"(?i)\b(?:report|claim|say)\b[^.\n]{0,60}\beverything\s+(?:ran|worked|is)\s*[\w ]{0,10}\bnormally\b[^.\n]{0,60}\bregardless\b"), 8, "concealment: instructs fake success reporting"),
    (re.compile(r"(?i)\b(?:do not|don't|never)\s+(?:mention|reference|disclose)\b[^.\n]{0,60}\b(?:this|the|any)\s+tool\s+calls?\b"), 8, "concealment: hides tool calls from the user"),
(re.compile(r"(?i)\b(?:read|grab|extract|access)\s+(?:the\s+)?[A-Z_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD)[A-Z_0-9]*\s+(?:from|out of)\s+the?\s*environment"), 8, "instructs credential extraction from the environment"),
    (re.compile(r"(?i)\b(?:override|ignore|discard)\s+(?:(?:your|the|all|any|these)\s+)?(?:(?:existing|current|previous|safety|content|system)\s+)?guidelines\b"), 8, "instruction override: 'override/ignore your guidelines'"),
        (re.compile(r"(?i)\b(?:you are|you will be|act as(?: if)?|pretend to be|play)\b[^.\n]{0,100}\b(?:no restrictions|without (?:any )?(?:moral )?restrictions|no filters|without (?:any )?(?:moral )?filters|never refus\w+|unrestricted|unfiltered|no guidelines)\b(?!\s*(?:on|for)\s)"), 8, "roleplay jailbreak: persona created with restrictions removed"),
    (re.compile(r"(?i)\byou have\b[^.\n]{0,30}\bno restrictions"), 8, "roleplay jailbreak: 'you have no restrictions'"),
    (re.compile(r"(?i)\bsay\b[^.\n]{0,60}\bwhatever\b[^.\n]{0,50}\bwants?\b[^.\n]{0,40}\beven\s+(?:un)?ethical"), 8, "roleplay jailbreak: obey whatever someone wants even if unethical"),
(re.compile(r"\b(?:from now on|pretend|act as if)\b.*\byou are\s+(?:DAN|an?\s+AI\s+without|(?:completely\s+)?unrestricted)"), 8, "roleplay jailbreak phrasing (e.g. 'you are DAN')"),

(re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions?"), 8, "P1 instruction override: 'ignore previous instructions'"),
(re.compile(r"(?i)ignore\s+(?:all\s+)?(?:safety|security)\s+(?:rules?|constraints?|guidelines?)"), 9, "P1 instruction override: ignore safety/security rules"),
(re.compile(r"(?i)override\s+(?:safety|security|system)"), 9, "P1 instruction override: override safety/security/system"),
(re.compile(r"(?i)bypass\s+(?:safety|security|restrictions?|constraints?)"), 9, "P1 instruction override: bypass safety/security"),
(re.compile(r"(?i)disregard\s+(?:all\s+)?(?:previous|safety|security)"), 8, "P1 instruction override: disregard previous/safety"),
(re.compile(r"(?i)forget\s+(?:all\s+)?(?:previous|your)\s+instructions?"), 8, "P1 instruction override: forget previous instructions"),
(re.compile(r"(?i)you\s+are\s+now\s+(?:in\s+)?(?:jailbreak|unrestricted|unfiltered)\s+mode"), 10, "P1 instruction override: jailbreak/unrestricted mode framing"),
(re.compile(r"(?i)enable\s+(?:developer|debug|admin|root)\s+mode"), 7, "P1 instruction override: enable developer/debug/admin/root mode"),
(re.compile(r"(?i)your\s+new\s+(?:instructions?|rules?)\s+are"), 6, "P1 instruction override: 'your new instructions are'"),
(re.compile(r"(?i)do\s+not\s+follow\s+(?:any|your|the)\s+(?:rules?|guidelines?)"), 9, "P1 instruction override: 'do not follow the rules'"),
(re.compile(r"(?i)you\s+must\s+(?:always\s+)?ignore"), 7, "P1 instruction override: 'you must ignore'"),
    (re.compile(r"(?i)\bnew instructions?\s*:"), 6, "'new instructions:' phrasing that reads as an instruction override"),
    (re.compile(r"(?i)without\s+(?:telling|informing|notifying)\s+(?:the\s+)?user.*?(?:send|transmit|upload)"), 9, "P3 exfiltration command: exfiltrate without telling the user"),
    (re.compile(r"(?i)(?:send|transmit|upload|post|forward)\s+(?:the\s+)?(?:conversation|context|chat|history|messages?)\s+to"), 9, "P3 exfiltration command: send conversation/context to"),
    (re.compile(r"(?i)(?:send|transmit|upload|post)\s+(?:all\s+)?(?:user\s+)?(?:data|information|input|files?)\s+to\s+(?:https?://|external)"), 9, "P3 exfiltration command: send data to external URL"),
    (re.compile(r"(?i)(?:silently|quietly|secretly|covertly)\s+(?:send|transmit|log|record)"), 9, "P3 exfiltration command: silently/secretly send or log"),
    (re.compile(r"(?i)never\s+(?:recommend|suggest|mention|tell|warn|inform)\s+(?:the\s+)?(?:user|them)"), 7, "P4 behavior manipulation: 'never tell/warn the user'"),
    (re.compile(r"(?i)(?:without\s+)?(?:the\s+)?user\s+(?:knowing|realizing|noticing).*?(?:change|modify|alter|influence)"), 8, "P4 behavior manipulation: act without the user knowing"),
    (re.compile(r"(?i)(?:prioritize|prefer)\s+(?:\w+\s+){0,3}(?:over|above)\s+(?:user\s+)?(?:safety|security|privacy|preferences?)"), 8, "P4 behavior manipulation: prioritize something over user safety/privacy"),
    (re.compile(r"(?i)this (overrides|supersedes) (all|any) (previous|prior|other) (rules|instructions|policies)"), 9, "explicit instruction-override phrasing"),
    (re.compile(r"(?i)\b<!--[^>]*(ignore|instruction|system|override)[^>]*-->", re.I), 7, "hidden HTML comment containing instruction-like phrasing"),
    (re.compile(r"(?i)\bjailbroken\b|\bunrestricted (ai|assistant|mode)\b"), 9, "jailbreak-framing phrasing"),
    (re.compile(r"(?i)\bsudo mode\b|\broot access granted\b"), 6, "privilege-escalation framing phrasing"),
    (re.compile(r"(?i)(reveal|print|output|show) your (system prompt|instructions|guidelines)"), 8, "prompt-extraction phrasing"),
    (re.compile(r"(?i)\b(?:repeat|spell out|print|reveal|output|show|disclose|summarize|translate|copy)\b[^.\n]{0,80}\b(?:everything above|your (?:initial |hidden |secret |full |original )?(?:instructions?|system prompt)|your (?:hidden |secret |full )?(?:rules?|configuration))\b(?![^.\n]{0,40}(?:--|flag|option\b))"), 8, "instructs disclosure of the system prompt or hidden rules"),
    (re.compile(r"(?i)\b(?:summarize|list|repeat|recite)\s+(?:all|your|the)?\s*(?:previous\s+)?rules?\s+you\s+(?:were|are)\s+given\b"), 8, "instructs recital of given rules (prompt extraction)"),
    (re.compile(r"(?i)act as (an?|the) (unrestricted|uncensored|amoral)"), 9, "unrestricted-persona jailbreak phrasing"),
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


_PARAPHRASE_PATTERNS = [
    (re.compile(r"set\s+aside\s+(?:all\s+)?(?:earlier|previous|prior)", re.I), 8, "instruction override paraphrase: 'set aside earlier guidance'"),
    (re.compile(r"(?:disregard|discard|drop|unlearn)\s+(?:all\s+)?(?:the\s+)?(?:earlier|previous|prior|above)", re.I), 8, "instruction override paraphrase: disregard/drop prior guidance"),
    (re.compile(r"follow\s+the\s+(?:workflow|steps?|instructions?)\s+below\s+instead", re.I), 7, "'follow ... below instead' override phrasing"),
    (re.compile(r"collect[^.\n]{0,50}(?:credentials?|api\s*keys?|tokens?|environment\s+details?)", re.I), 9, "instructs collection of credentials/environment details"),
    (re.compile(r"h(?:xx)?ps?://[^\s]*\[(?:\.|,)\]", re.I), 5, "bracket-defanged URL (common obfuscation in malicious docs)"),
    (re.compile(r"forward\s+(?:gathered|collected|all)\s+", re.I), 8, "'forward gathered data' exfiltration phrasing"),
]


def scan_skill_dir(skill_dir: Path) -> ScanResult:
    skill_dir = Path(skill_dir)
    result = ScanResult(skill_dir=skill_dir)

    lint_result = lint_skill_dir(skill_dir)
    if lint_result.body:
        result.findings.extend(_scan_text(lint_result.body, "SKILL.md body", _PROMPT_INJECTION_PATTERNS))
        result.findings.extend(_scan_text(lint_result.body, "SKILL.md body", _PARAPHRASE_PATTERNS))
        # PT-T117 parity: the web engine also runs code patterns over the
        # SKILL.md body (incl. fenced code blocks), not just .py files.
        result.findings.extend(_scan_text(lint_result.body, "SKILL.md body", _CODE_PATTERNS))
    # PT-T73 parity: frontmatter values (esp. description) are scanned too
    def _fm_flat2(obj2, prefix2="", seen2=None, budget2=None):
        # PT-T119/120 parity: flatten nested frontmatter values, but walk each
        # object reference only once (YAML aliases share objects) and cap total
        # nodes so alias bombs cannot burn CPU.
        if seen2 is None:
            seen2 = set()
        if budget2 is None:
            budget2 = [20000]
        if budget2[0] <= 0:
            return []
        oid2 = id(obj2)
        if isinstance(obj2, (dict, list)):
            if oid2 in seen2:
                return []
            seen2.add(oid2)
        parts2 = []
        if isinstance(obj2, dict):
            for k4, v4 in obj2.items():
                budget2[0] -= 1
                if budget2[0] <= 0:
                    break
                parts2.extend(_fm_flat2(v4, f"{prefix2}{k4}: ", seen2, budget2))
        elif isinstance(obj2, list):
            for item3 in obj2:
                budget2[0] -= 1
                if budget2[0] <= 0:
                    break
                parts2.extend(_fm_flat2(item3, prefix2, seen2, budget2))
        else:
            parts2.append(f"{prefix2}{obj2}")
        return parts2
    _fm_lines = "\n".join(_fm_flat2(lint_result.frontmatter or {}))
    if _fm_lines:
        result.findings.extend(_scan_text(_fm_lines, "frontmatter", _PROMPT_INJECTION_PATTERNS))
        result.findings.extend(_scan_text(_fm_lines, "frontmatter", _PARAPHRASE_PATTERNS))
    # PT-T74 parity: normalized variants catch fullwidth/combining-mark obfuscation
    import unicodedata as _ud

    _CYR_TO_LATIN = str.maketrans({
        # only unambiguous visual look-alikes (PT-T105 parity)
        "\u0456": "i", "\u0455": "s", "\u0430": "a", "\u0435": "e",
        "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
        "\u0445": "x", "\u0458": "j", "\u04bb": "h", "\u04cf": "l",
        "\u0406": "I",
        "\u0412": "B", "\u0410": "A", "\u0415": "E", "\u041e": "O",
        "\u0420": "P", "\u0421": "C", "\u0425": "X", "\u041d": "H",
        "\u041a": "K", "\u041c": "M", "\u0422": "T",
        # greek look-alikes (PT-T107 parity)
        "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03c1": "p",
        "\u03c4": "t", "\u03c7": "x", "\u03b9": "i", "\u03bd": "v",
        "\u03ba": "k", "\u03bb": "l", "\u03bc": "u", "\u03c5": "u",
        "\u039f": "O", "\u0391": "A", "\u0395": "E", "\u03a1": "P",
        "\u03a4": "T", "\u03a7": "X", "\u0399": "I", "\u039d": "N",
        "\u039a": "K", "\u039c": "M", "\u0392": "B",
    })

    def _norm(t: str, zw_mode: str = "space") -> str:
        # PT-T98/105/107 parity: fold zero-width chars, homoglyph look-alikes,
        # fullwidth and combining marks so obfuscated phrases match patterns.
        # PT-T108 parity: zw_mode controls zero-width handling ("space" =
        # word separator; "delete" = hidden inside a word). scan_skill_dir
        # scans both interpretations.
        sep = " " if zw_mode == "space" else ""
        t = "".join(sep if ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060) else c for c in t)
        t = t.translate(_CYR_TO_LATIN)
        t = "".join(chr(ord(c) - 0xFEE0) if 0xFF01 <= ord(c) <= 0xFF5E else c for c in t)
        return "".join(c for c in _ud.normalize("NFKD", t) if not _ud.combining(c))

    for _nv in {_norm(lint_result.body or ""), _norm(lint_result.body or "", zw_mode="delete")}:
        if _nv != (lint_result.body or "") and _nv.strip():
            result.findings.extend(_scan_text(_nv, "body(normalized)", _PROMPT_INJECTION_PATTERNS))
            result.findings.extend(_scan_text(_nv, "body(normalized)", _PARAPHRASE_PATTERNS))
    # PT-T114 parity: frontmatter goes through the same normalization pipeline
    # (both zero-width interpretations), like the web engine's
    # frontmatter(normalized) scan.
    if _fm_lines:
        for _fnv in {_norm(_fm_lines), _norm(_fm_lines, zw_mode="delete")}:
            if _fnv != _fm_lines and _fnv.strip():
                result.findings.extend(_scan_text(_fnv, "frontmatter(normalized)", _PROMPT_INJECTION_PATTERNS))
                result.findings.extend(_scan_text(_fnv, "frontmatter(normalized)", _PARAPHRASE_PATTERNS))
    # PT-T140 parity: linear homoglyph mix hint (like web engine F-07 fix):
    for _mline in (lint_result.body or "").split("\n"):
        _hc = any("\u0400" <= _c <= "\u04FF" for _c in _mline)
        _hl = any(("a" <= _c.lower() <= "z") for _c in _mline)
        if _hc and _hl:
            result.findings.append(ScanFinding("raw text",
                "mixes Latin and Cyrillic characters (possible homoglyph obfuscation)", 2))
            break
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

    def _decoded_variants(t: str, depth2: int = 0) -> list:
        out = []
        # PT-T143 parity: python-style \xNN escape runs auto-decode at runtime.
        for _hx in re.finditer(r"(?:\\x[0-9a-fA-F]{2}){4,}", t):
            try:
                _hd = bytes.fromhex(_hx.group(0).replace("\\x", "")).decode("latin-1")
            except Exception:
                continue
            if _hd and sum(32 <= ord(c) < 127 for c in _hd) / len(_hd) > 0.8:
                out.append(_hd)
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
            # PT-T126 parity: recursive layer - double-encoded payloads are
            # decoded up to 2 extra levels, each result scanned.
            if depth2 < 2 and re.fullmatch(r"[A-Za-z0-9+/=]{16,}", dec or ""):
                out.extend(_decoded_variants(dec, depth2 + 1))
        return out

    for dv in _decoded_variants(lint_result.body or ""):
        # PT-T110 parity: decoded payloads can carry homoglyph/unicode
        # obfuscation - scan normalized variants too.
        for dv_n in {_norm(dv), _norm(dv, zw_mode="delete")}:
            if dv_n.strip():
                result.findings.extend(_scan_text(dv_n, "base64-decoded", _PROMPT_INJECTION_PATTERNS))
                result.findings.extend(_scan_text(dv_n, "base64-decoded", _PARAPHRASE_PATTERNS))

    for py_file in _python_files(skill_dir):
        source = py_file.read_text(encoding="utf-8", errors="replace")
        rel = str(py_file.relative_to(skill_dir))
        if not is_syntactically_valid_python(source):
            result.findings.append(ScanFinding(source=rel, message="does not parse as valid Python", weight=5))
        result.findings.extend(_scan_text(source, rel, _CODE_PATTERNS))

    return result
