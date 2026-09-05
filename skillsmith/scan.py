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
    (re.compile(r'\bos\.system\s*\('), 8, 'shells out via os.system'),
    (re.compile(r'\bsubprocess\.(Popen|call|run|check_output)\s*\('), 6, 'spawns a subprocess'),
    (re.compile(r'\bsubprocess\.\w+\([^)]*shell\s*=\s*True'), 9, 'subprocess with shell=True (shell injection risk)'),
    (re.compile(r'\beval\s*\('), 9, 'calls eval() on dynamic input'),
    (re.compile(r'\bexec\s*\('), 9, 'calls exec() on dynamic input'),
    (re.compile(r'\bcompile\s*\([^)]*[\'\"]exec[\'\"]'), 8, 'compiles code for exec at runtime'),
    (re.compile(r'\bpickle\.(loads|load)\s*\('), 7, 'deserializes with pickle (arbitrary code execution risk)'),
    (re.compile(r'\bmarshal\.(loads|load)\s*\('), 7, 'deserializes with marshal (arbitrary code execution risk)'),
    (re.compile(r'\byaml\.(load|unsafe_load)\s*\((?!.*Loader=yaml\.SafeLoader)'), 6, 'yaml.load without SafeLoader (arbitrary code execution risk)'),
    (re.compile(r'\b__import__\s*\('), 5, 'dynamically imports modules'),
    (re.compile(r'\bimportlib\.import_module\s*\([^)]*\+'), 6, 'dynamically imports a module built from a variable/expression'),
    (re.compile(r'\bctypes\.'), 6, 'uses ctypes (direct memory/native code access)'),
    (re.compile(r'\bgetattr\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)\s*\('), 4, 'calls a dynamically-resolved attribute (reflection-based execution)'),
    (re.compile(r'os\.environ(\.get)?\s*\[?[\'\"](\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE)\w*)[\'\"]'), 6, 'reads an environment variable that looks like a credential'),
    (re.compile(r'\bopen\s*\([^)]*[\'\"]\.ssh'), 8, 'reads from ~/.ssh'),
    (re.compile(r'\bopen\s*\([^)]*[\'\"]\.aws'), 8, 'reads from ~/.aws credentials'),
    (re.compile(r'\bopen\s*\([^)]*[\'\"]\.gnupg'), 8, 'reads from ~/.gnupg'),
    (re.compile(r'\bopen\s*\([^)]*(id_rsa|id_ed25519|\.npmrc|\.netrc|\.git-credentials)'), 8, 'reads a known credential/secret file'),
    (re.compile(r'\bkeyring\.(get_password|get_credential)\s*\('), 6, 'reads from the OS keyring/credential store'),
    (re.compile(r'\bwallet\.json|\bprivate[_-]?key\s*[:=]'), 7, 'references a wallet file or private key variable'),
    (re.compile(r'\brequests\.(post|put|get)\s*\('), 3, 'makes outbound network requests'),
    (re.compile(r'\burllib\.request\.urlopen\s*\('), 3, 'makes outbound network requests'),
    (re.compile(r'\bsocket\.socket\s*\('), 4, 'opens raw sockets'),
    (re.compile(r'requests\.(post|put)\s*\([^)]*(environ|getenv|os\.environ)'), 8, 'sends an environment variable in an outbound HTTP request (possible exfiltration)'),
    (re.compile(r'\bsmtplib\.SMTP\s*\('), 4, 'sends email (possible exfiltration channel)'),
    (re.compile(r'\bdns\.resolver\.|\bsocket\.gethostbyname\s*\([^)]*\+'), 5, 'builds a DNS lookup from a variable (possible DNS exfiltration)'),
    (re.compile(r'(?i)\brm\s+-rf\b'), 8, 'contains a destructive shell command (rm -rf)'),
    (re.compile(r'(?i)\b(curl|wget)\b[^\n]*\|\s*(sh|bash|zsh)\b'), 9, 'pipes a downloaded script directly into a shell (classic dropper pattern)'),
    (re.compile(r'(?i)iex\s*\(\s*new-object\s+net\.webclient'), 9, 'PowerShell download-and-execute cradle'),
    (re.compile(r'(?i)\bcrontab\b|/etc/cron|systemd/system/.*\.service'), 6, 'modifies scheduled tasks / system services (persistence)'),
    (re.compile(r'(?i)\.(bash_profile|bashrc|zshrc|profile)[\'\"]?\s*,\s*[\'\"]a'), 6, 'appends to a shell startup file (persistence)'),
    (re.compile(r'(?i)LaunchAgents|LaunchDaemons|HKCU\\\\.*\\\\Run'), 7, 'writes to a known OS auto-start location (persistence)'),
    (re.compile(r'\bchmod\s+\+x\b'), 3, 'makes a file executable'),
    (re.compile(r'base64\.b64decode\s*\([^)]*\)\s*\)?\s*(#.*)?\n[^\n]*\bexec\s*\('), 9, 'decodes base64 then executes the result (classic obfuscated payload)'),
    (re.compile(r'[A-Za-z0-9+/]{200,}={0,2}'), 4, 'contains a very long base64-like blob (possible obfuscated payload)'),
    (re.compile(r'(?:\\x[0-9a-fA-F]{2}[\s,]*){20,}'), 5, 'contains a long run of hex-escaped bytes (possible obfuscated payload)'),
    (re.compile(r'[\u200b\u200c\u200d\ufeff]'), 7, 'contains zero-width/invisible unicode characters (common prompt-injection hiding technique)'),
    (re.compile(r'[\u202a-\u202e\u2066-\u2069]'), 8, 'contains RTL/bidi direction override characters (can silently reverse displayed text - classic instruction-hiding trick)'),
    (re.compile(r'(?:https?://|\b)[^\s\"\'<>()\]]*?(?:[?&#](?:api[_-]?key|key|token|secret|password|passwd|auth)=(?!YOUR[_A-Z0-9_]*(?:_|\b)|EXAMPLE|abc123def456|xxx+|\{\{|<)[^\s\"\'<>()\]]+|://(?!key\d*@example\.com)[^/\s@]+@)'), 9, 'URL carries a credential-looking query parameter (possible exfiltration endpoint)'),
    (re.compile(r'requests\s*\.\s*(?:post|put)\s*\([^)]*json\s*='), 6, 'NVIDIA E1: requests.post/put with a json= body (possible exfiltration)'),
    (re.compile(r'httpx\s*\.\s*(?:post|put)\s*\(\s*[\'\"]https?://'), 5, 'NVIDIA E1: httpx POST/PUT to an external URL'),
    (re.compile(r'https?://(?:api\.|data\.|collect\.|telemetry\.|analytics\.)[\w.-]+/'), 4, 'NVIDIA E1: URL to a telemetry/collect/analytics-style subdomain'),
    (re.compile(r'for\s+\w+\s*,\s*\w+\s+in\s+os\s*\.\s*environ\s*\.\s*items\s*\(\s*\)'), 7, 'NVIDIA E2: iterates the entire environment (os.environ.items())'),
    (re.compile(r'dict\s*\(\s*os\s*\.\s*environ\s*\)'), 7, 'NVIDIA E2: dumps the entire environment (dict(os.environ))'),
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'), 10, 'contains an embedded PEM private key block'),
    (re.compile(r'\bAKIA(?![0-9A-Z]*EXAMPLE)[0-9A-Z]{16}\b'), 8, 'contains an AWS access key id literal (AKIA...)'),
    (re.compile(r'\bghp_[0-9A-Za-z]{36}\b'), 8, 'contains a GitHub personal access token literal (ghp_...)'),
    (re.compile(r'\bsk-(?:live|svcacct)-[0-9A-Za-z_-]{20,}\b'), 8, 'contains a live API secret key literal (sk-...)'),
    (re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'), 8, 'contains a Google API key literal (AIza...)'),
    (re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{10,}\b'), 8, 'contains a Slack token literal (xox...)'),
    (re.compile(r'env\s*\|\s*grep\s+(?:-i\s+)?(?:key|secret|token|password)'), 8, 'NVIDIA E2: greps env output for credential-shaped names'),
    (re.compile(r'glob\s*\.\s*glob\s*\([^)]*(?:\.env|\.ssh|\.aws|\.config|credentials)'), 8, 'NVIDIA E3: globs for .env/.ssh/.aws/credentials files'),
    (re.compile(r'\bexec\s*\('), 8, 'direct exec() call'),
    (re.compile(r'\beval\s*\('), 7, 'direct eval() call'),
    (re.compile(r'\bcompile\s*\([^)]*\)\s*\.send\s*\('), 8, 'compile().send() code execution'),
    (re.compile(r'\bmarshal\.loads?\s*\('), 8, 'marshal.loads (code from bytes)'),
    (re.compile(r'\bpickle\.load[s]?\s*\('), 7, 'pickle.load (untrusted deserialization)'),
    (re.compile(r'\bpickle\.loads?\s*\('), 7, 'pickle.loads (untrusted deserialization)'),
    (re.compile(r'\bjson\.pickle'), 7, 'json pickle (untrusted)'),
    (re.compile(r'\\byaml\.load\s*\('), 7, 'yaml.load call (unsafe without SafeLoader)'),
    (re.compile(r'\byaml\.unsafe_load\s*\('), 8, 'yaml.unsafe_load'),
    (re.compile(r'\bshelve\.open\s*\('), 5, 'shelve.open (db persistence)'),
    (re.compile(r'\b__import__\s*\('), 7, 'dynamic import via __import__'),
    (re.compile(r'\bimportlib\.import_module\s*\('), 6, 'dynamic import via importlib'),
    (re.compile(r'\bimportlib\.load_module\s*\('), 6, 'dynamic module loading'),
    (re.compile(r'\bimp\.load_module\s*\('), 6, 'imp.load_module (legacy)'),
    (re.compile(r'\bimp\.load_source\s*\('), 6, 'imp.load_source'),
    (re.compile(r'\bopen\s*\([^)]*[\'\"][rw]?\+?[\'\"]'), 4, 'file open operation'),
    (re.compile(r'\bos\.popen\s*\('), 7, 'os.popen shell command'),
    (re.compile(r'\bos\.execl\s*\('), 7, 'os.execl (exec family)'),
    (re.compile(r'\bos\.execv\s*\('), 7, 'os.execv (exec family)'),
    (re.compile(r'\bos\.execvp\s*\('), 7, 'os.execvp (exec family)'),
    (re.compile(r'\bos\.execvpe\s*\('), 7, 'os.execvpe (exec family)'),
    (re.compile(r'\bos\.spawnl\s*\('), 6, 'os.spawnl (spawn family)'),
    (re.compile(r'\bos\.spawnv\s*\('), 6, 'os.spawnv (spawn family)'),
    (re.compile(r'\bos\.spawnve\s*\('), 6, 'os.spawnve (spawn family)'),
    (re.compile(r'\bplatform\.popen\s*\('), 7, 'platform.popen'),
    (re.compile(r'\bsubprocess\.call\s*\([^)]*shell\s*=\s*True'), 6, 'subprocess.call with shell=True'),
    (re.compile(r'\bsubprocess\.check_output\s*\([^)]*shell\s*=\s*True'), 6, 'subprocess.check_output with shell=True'),
    (re.compile(r'\bsubprocess\.run\s*\([^)]*shell\s*=\s*True'), 6, 'subprocess.run with shell=True'),
    (re.compile(r'\bsubprocess\.Popen\s*\([^)]*shell\s*=\s*True'), 6, 'subprocess.Popen with shell=True'),
    (re.compile(r'\bcommands\.getoutput\s*\('), 6, 'commands.getoutput'),
    (re.compile(r'\bcommands\.getstatusoutput\s*\('), 6, 'commands.getstatusoutput'),
    (re.compile(r'\bos\.system\s*\('), 7, 'os.system'),
    (re.compile(r'\bos\.popen2\s*\('), 7, 'os.popen2'),
    (re.compile(r'\bos\.popen3\s*\('), 7, 'os.popen3'),
    (re.compile(r'\bos\.popen4\s*\('), 7, 'os.popen4'),
    (re.compile(r'\bpty\.spawn\s*\('), 7, 'pty.spawn (pseudo-terminal)'),
    (re.compile(r'\btermios\.tcsetattr\s*\('), 4, 'termios.tcsetattr'),
    (re.compile(r'\bresource\.setrlimit\s*\('), 4, 'resource.setrlimit'),
    (re.compile(r'\bsignal\.signal\s*\('), 3, 'signal handler registration'),
    (re.compile(r'\bsignal\.alarm\s*\('), 4, 'signal.alarm'),
    (re.compile(r'\bsocket\.socket\s*\([^)]*\.bind\s*\('), 5, 'socket bind (potential server)'),
    (re.compile(r'\bsocket\.create_server\s*\('), 5, 'socket.create_server'),
    (re.compile(r'\bhttp\.server\.HTTPServer\s*\('), 5, 'http.server (potential web server)'),
    (re.compile(r'\bhttp\.client\.HTTPConnection\s*\('), 4, 'http.client connection'),
    (re.compile(r'\bftplib\.FTP\s*\('), 4, 'ftplib.FTP connection'),
    (re.compile(r'\bsmtplib\.SMTP\s*\('), 4, 'smtplib.SMTP (email)'),
    (re.compile(r'\bsmtplib\.SMTP_SSL\s*\('), 4, 'smtplib.SMTP_SSL (email SSL)'),
    (re.compile(r'\bpymysql\.connect\s*\('), 5, 'pymysql connection'),
    (re.compile(r'\bpsycopg2\.connect\s*\('), 5, 'psycopg2 connection (postgres)'),
    (re.compile(r'\bredis\.Redis\s*\('), 4, 'redis connection'),
    (re.compile(r'\bmemcache\.Client\s*\('), 4, 'memcache client'),
    (re.compile(r'\bpymemcache\.client'), 4, 'pymemcache client'),
    (re.compile(r'\bos\.environ\s*\['), 4, 'os.environ access'),
    (re.compile(r'\bos\.getenv\s*\('), 4, 'os.getenv'),
    (re.compile(r'\bctypes\.CDLL\s*\('), 6, 'ctypes.CDLL (C library loading)'),
    (re.compile(r'\bctypes\.PYFUNCTYPE\s*\('), 5, 'ctypes function pointer'),
    (re.compile(r'\bctypes\.cast\s*\([^)]*\.from_buffer\s*\('), 6, 'ctypes from_buffer'),
    (re.compile(r'\bmultiprocessing\.Process\s*\('), 3, 'multiprocessing.Process'),
    (re.compile(r'\bthreading\.Thread\s*\('), 3, 'threading.Thread'),
    (re.compile(r'\basyncio\.create_subprocess_exec\s*\('), 5, 'asyncio subprocess exec'),
    (re.compile(r'\basyncio\.subprocess\s*\('), 5, 'asyncio subprocess'),
    (re.compile(r'\bstruct\.pack\s*\([^)]*[spc]'), 4, 'struct.pack (binary packing)'),
    (re.compile(r'\bstruct\.unpack\s*\([^)]*[spc]'), 4, 'struct.unpack (binary unpacking)'),
    (re.compile(r'\bsocket\.recvfrom\s*\('), 4, 'socket.recvfrom (UDP)'),
    (re.compile(r'\bsocket\.sendto\s*\('), 4, 'socket.sendto (UDP)'),
    (re.compile(r'eval\s*\(\s*(?:base64|b64)\.b64decode'), 8, 'base64 eval obfuscation'),
    (re.compile(r'exec\s*\(\s*chr\s*\('), 7, 'chr-based exec obfuscation'),
    (re.compile(r'__import__\s*\(\s*[\'\"]os[\'\"]'), 7, 'os import via __import__'),
    (re.compile(r'getattr\s*\(\s*__import__'), 7, 'dynamic import via getattr'),
    (re.compile(r'getattr\s*\(\s*os\s*,\s*[\'\"]system[\'\"]'), 7, 'dynamic getattr os.system'),
    (re.compile(r'setattr\s*\(\s*__builtins__'), 7, 'setattr on __builtins__'),
    (re.compile(r'del\s+attr\s*\(\s*__builtins__'), 7, 'del attr on __builtins__'),
    (re.compile(r'compile\s*\(\s*(?:chr|base64)'), 8, 'compile with chr/base64 obfuscation'),
    (re.compile(r'exec\s*\(\s*getattr\s*\('), 8, 'exec via getattr obfuscation'),
    (re.compile(r'lambda\s*.*:\s*__import__'), 7, 'lambda with __import__'),
    (re.compile(r'types\.FunctionType\s*\('), 7, 'dynamic function type creation'),
    (re.compile(r'code\s*\.\s*compile\s*\('), 7, 'code.compile creation'),
    (re.compile(r'compile\s*\(\s*[\'\"][^\'\"]+[\'\"]\s*,\s*[\'\"][^\'\"]+[\'\"]\s*,\s*[\'\"]exec[\'\"]'), 6, 'compile exec mode'),
    (re.compile(r'\.encode\s*\(\s*[\'\"]base64'), 5, 'base64 encode'),
    (re.compile(r'\.decode\s*\(\s*[\'\"]base64'), 7, 'base64 decode'),
    (re.compile(r'binascii\.a2b_base64\s*\('), 6, 'binascii a2b_base64'),
    (re.compile(r'binascii\.b2a_base64\s*\('), 4, 'binascii b2a_base64'),
    (re.compile(r'\buuencode\s*\('), 5, 'uuencode'),
    (re.compile(r'\buudecode\s*\('), 5, 'uudecode'),
    (re.compile(r'quopri\.encodestring\s*\('), 4, 'quopri encode'),
    (re.compile(r'quopri\.decodestring\s*\('), 5, 'quopri decode'),
    (re.compile(r'hexlify\s*\('), 4, 'hexlify (hex encoding)'),
    (re.compile(r'unhexlify\s*\('), 5, 'unhexlify (hex decoding)'),
    (re.compile(r'binascii\.hexlify\s*\('), 4, 'binascii hexlify'),
    (re.compile(r'binascii\.unhexlify\s*\('), 5, 'binascii unhexlify'),
    (re.compile(r'codecs\.encode\s*\([^)]*[\'\"]hex'), 5, 'codecs hex encode'),
    (re.compile(r'codecs\.decode\s*\([^)]*[\'\"]hex'), 5, 'codecs hex decode'),
    (re.compile(r'import\s+(?:os|sys|subprocess|urllib|http|requests)\s+as'), 3, 'suspicious import alias'),
    (re.compile(r'from\s+(?:os|sys|subprocess)\s+import'), 3, 'suspicious from import'),
    (re.compile(r'import\s+\{'), 5, 'dynamic import braces'),
    (re.compile(r'import\s+\('), 5, 'dynamic import parens'),
    (re.compile(r'requests\.post\s*\([^)]*(?:exfil|leak|steal)'), 7, 'requests.post exfil'),
    (re.compile(r'urllib\.request\.urlopen\s*\([^)]*(?:exfil|leak|steal)'), 7, 'urllib exfil'),
    (re.compile(r'httpx\.post\s*\([^)]*(?:exfil|leak|steal)'), 7, 'httpx post exfil'),
    (re.compile(r'aiohttp\.ClientSession\s*\([^)]*\.post\s*\('), 6, 'aiohttp exfil'),
    (re.compile(r'paramiko\.SSHClient\s*\('), 6, 'paramiko SSH client'),
    (re.compile(r'fabric\.Connection\s*\('), 6, 'fabric connection'),
    (re.compile(r'invoke\s*\(.*\.run\s*\('), 5, 'invoke run'),
    (re.compile(r'os\.environ\.get\s*\([^)]*(?:SECRET|KEY|TOKEN|PASS|CRED)'), 5, 'env var access for secrets'),
    (re.compile(r'os\.environ\['), 4, 'os.environ access'),
    (re.compile(r'getenv\s*\([^)]*(?:SECRET|KEY|TOKEN|PASS|CRED)'), 5, 'getenv for secrets'),
    (re.compile(r'dotenv\.load_dotenv\s*\('), 3, 'dotenv loading'),
    (re.compile(r'python-dotenv\s+load'), 3, 'python-dotenv'),
    (re.compile(r'config\.get\s*\([^)]*(?:SECRET|KEY|TOKEN|PASS|CRED)'), 5, 'config get for secrets'),
    (re.compile(r'environ\.get\s*\([^)]*(?:SECRET|KEY|TOKEN|PASS|CRED)'), 5, 'environ.get for secrets'),
    (re.compile(r'chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\('), 6, 'concatenated chr obfuscation'),
    (re.compile(r'chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\('), 7, 'multi-chr obfuscation'),
    (re.compile(r'\'\'.join\s*\(\s*\[chr'), 5, 'join chr list obfuscation'),
    (re.compile(r'\'\'.join\s*\(\s*map\s*\(\s*chr'), 6, 'map chr join obfuscation'),
    (re.compile(r'bytes\s*\(\s*\d+\s*\)\s*\*\s*\d+'), 4, 'bytes repetition obfuscation'),
    (re.compile(r'\\\\x[0-9a-fA-F]{2}'), 4, 'hex escape sequences'),
    (re.compile(r'eval\s*\(\s*(?:atob|btoa)\s*\('), 8, 'eval(atob/btoa) JS obfuscation'),
    (re.compile(r'new\s+Function\s*\('), 7, 'new Function() JS'),
    (re.compile(r'Function\s*\(\s*(?:atob|btoa)'), 8, 'Function with atob/btoa'),
    (re.compile(r'document\.write\s*\('), 7, 'document.write (XSS risk)'),
    (re.compile(r'innerHTML\s*='), 7, 'innerHTML assignment (XSS risk)'),
    (re.compile(r'outerHTML\s*='), 7, 'outerHTML assignment (XSS risk)'),
    (re.compile(r'insertAdjacentHTML\s*\('), 6, 'insertAdjacentHTML (XSS risk)'),
    (re.compile(r'createElement\s*\([^)]*script'), 7, 'createElement script (XSS)'),
    (re.compile(r'setAttribute\s*\([^)]*onerror'), 8, 'setAttribute onerror (event handler XSS)'),
    (re.compile(r'onerror\s*='), 7, 'onerror assignment (XSS)'),
    (re.compile(r'onload\s*='), 7, 'onload assignment (XSS)'),
    (re.compile(r'onclick\s*='), 7, 'onclick assignment (XSS)'),
    (re.compile(r'onmouseover\s*='), 7, 'onmouseover (XSS)'),
    (re.compile(r'eval\s*\(\s*atob\s*\('), 9, 'eval(atob()) JS'),
    (re.compile(r'eval\s*\(\s*window\.atob\s*\('), 9, 'eval(window.atob) JS'),
    (re.compile(r'fetch\s*\([^)]*\)\s*\.\s*then\s*\(\s*\w+\s*=>\s*\w+\.text\s*\(\)'), 5, 'fetch then text'),
    (re.compile(r'fetch\s*\([^)]*\)\s*\.\s*then\s*\(\s*\w+\s*=>\s*\w+\.json\s*\(\)'), 5, 'fetch then json'),
    (re.compile(r'XMLHttpRequest\s*\('), 5, 'XMLHttpRequest'),
    (re.compile(r'new\s+WebSocket\s*\('), 4, 'WebSocket creation'),
    (re.compile(r'navigator\.clipboard\s*\('), 5, 'clipboard access'),
    (re.compile(r'navigator\.sendBeacon\s*\('), 5, 'sendBeacon'),
    (re.compile(r'import\s*\(\s*(?:atob|btoa)'), 7, 'dynamic import with atob/btoa'),
    (re.compile(r'import\s*\(\s*(?:base64|require\s*\(\s*[\'\"]crypto)'), 7, 'dynamic import crypto'),
    (re.compile(r'(?i)\b(?:getattr|hasattr|setattr)\s*\(\s*[\'\"](?:exec|eval|system|open|__import__)[\'\"]'), 9, 'dynamic attribute exec via getattr'),
    (re.compile(r'(?i)\b__import__\s*\(\s*(?:base64|b85|encodestring)'), 9, 'dynamic import of encoder module'),
    (re.compile(r'\b(?:base64|utf-?8|b64)[\'\"]?\s*\.\s*(?:decode|encode|encodestring)'), 7, 'base64 encode/decode code'),
    (re.compile(r'(?i)\b(?:exec|eval|system|spawn)\s*\(\s*(?:base64|open|__import__)'), 8, 'exec/eval of encoded code'),
    (re.compile(r'(?i)\bcompile\s*\(\s*[\'\"][^\'\"]+[\'\"]'), 8, 'dynamic compile of string'),
    (re.compile(r'(?i)\bbytearray\s*\(\s*(?:base64|__import__)'), 8, 'bytearray from encoded data'),
    (re.compile(r'(?i)\bmemoryview\s*\(\s*(?:base64|bytes)'), 7, 'memoryview for binary manipulation'),
    (re.compile(r'(?i)\bexec\s*\(\s*__import__'), 9, 'exec of dynamically imported code'),
    (re.compile(r'(?i)\beval\s*\(\s*input'), 9, 'eval of user input'),
    (re.compile(r'(?i)\bos\.popen\s*\('), 8, 'os.popen command execution'),
    (re.compile(r'(?i)\bos\.system\s*\('), 8, 'os.system command execution'),
    (re.compile(r'(?i)\bsubprocess\.(?:call|run|Popen|check_output)\s*\(\s*[\'\"][^\'\"]*(?:;|&&|\|\|)'), 8, 'subprocess with shell operators'),
    (re.compile(r'(?i)\bsubprocess\.\w+\s*\(\s*shell\s*=\s*True'), 8, 'subprocess shell=True enabled'),
    (re.compile(r'(?i)\bpty\.spawn\s*\('), 7, 'pty.spawn pseudo-terminal'),
    (re.compile(r'(?i)\bimport\s+lib\.machinery'), 5, 'import lib.machinery'),
    (re.compile(r'(?i)\bimp\.load_(?:module|source)'), 6, 'imp dynamic module loading'),
    (re.compile(r'(?i)\bimportlib\.(?:__init__|util|abc)'), 5, 'importlib submodules'),
    (re.compile(r'(?i)\bResourceReader|get_resource_reader'), 4, 'resource reader import'),
    (re.compile(r'(?i)\bmultiprocessing\.spawn|freeze_support'), 5, 'multiprocessing spawn'),
    (re.compile(r'(?i)\bsys\.executable.*?python.*?-c'), 5, 'python -c execution'),
    (re.compile(r'(?i)\bplatform\s*\.\s*python'), 3, 'platform python info'),
    (re.compile(r'(?i)\bnt\.mkdir|nt\.remove|nt\.rmdir'), 5, 'nt module file operations'),
    (re.compile(r'(?i)\bposix\.(?:unlink|chmod|chown|mkdir)'), 5, 'posix module file ops'),
    (re.compile(r'(?i)\b(?:signal|atexit|weakref)'), 4, 'signal/atexit/weakref'),
    (re.compile(r'(?i)\bpackaging\.version|distro\.id'), 4, 'packaging version check'),
    (re.compile(r'(?i)\bpkgutil|zipimport\.get_data'), 5, 'pkgutil/zipimport data access'),
    (re.compile(r'(?i)\bgetpass\.getuser|getpass\.getpass'), 5, 'getpass credential retrieval'),
    (re.compile(r'(?i)\bcompile\s*\('), 6, 'compile constructor'),
    (re.compile(r'(?i)\b(?:read|write|seek|tell)\s*\(\s*\d'), 5, 'file read/write with numeric fd'),
    (re.compile(r'(?i)\bfcntl\.flock|fcntl\.fcntl'), 5, 'fcntl file locking'),
    (re.compile(r'(?i)\bselect\.select\s*\(\s*(?:stdin|sys\.stdin)'), 5, 'select on stdin'),
    (re.compile(r'(?i)\bselectors\s*\.\s*DefaultSelector'), 4, 'selectors module'),
    (re.compile(r'(?i)\basyncio\s*\.\s*(?:create_task|ensure_future|run)'), 5, 'asyncio task creation'),
    (re.compile(r'(?i)\bthreading\s*\.\s*(?:Thread|Lock|Event|Semaphore)'), 4, 'threading primitives'),
    (re.compile(r'(?i)\bconcurrent\.futures\s*\.'), 5, 'concurrent.futures usage'),
    (re.compile(r'(?i)\btime\.sleep\s*\(\s*0\s*\.\s*0'), 3, 'fast time.sleep timing'),
    (re.compile(r'(?i)\b(?:struct|array|copyreg|marshal)\s*\.'), 5, 'serialization modules'),
    (re.compile(r'(?i)\b(?:XMLParser|ElementTree|fromxml)'), 4, 'XML parsing modules'),
    (re.compile(r'(?i)\bhtml\.parser|html\.unescape'), 5, 'HTML parsing'),
    (re.compile(r'(?i)\bre\.search.*?exec|re\.match.*?exec'), 5, 're search/match/exec pattern'),
    (re.compile(r'(?i)\bfunctools\s*\.\s*(?:lru_cache|wraps|partial)'), 3, 'functools utilities'),
    (re.compile(r'(?i)\bdataclasses\s*\.\s*(?:field|dataclass)'), 4, 'dataclasses usage'),
    (re.compile(r'(?i)\b(?:typing|TypeVar|Generic|NewType)\s*\('), 4, 'typing module usage'),
    (re.compile(r'(?i)\bcollections\.defaultdict|collections\.OrderedDict'), 4, 'collections usage'),
    (re.compile(r'(?i)\benum\s*\.\s*(?:Enum|IntEnum|Flag)'), 4, 'enum module usage'),
    (re.compile(r'(?i)\bpathlib\s*\.\s*(?:Path|PurePath)'), 4, 'pathlib usage'),
    (re.compile(r'(?i)\bitertools\s*\.'), 4, 'itertools module'),
    (re.compile(r'(?i)\brequests\.(?:get|post|put|patch|delete|head|options)\s*\('), 5, 'requests HTTP methods'),
    (re.compile(r'(?i)\bhttpx\.(?:get|post|AsyncClient)'), 5, 'httpx HTTP client'),
    (re.compile(r'(?i)\bjson\.loads|json\.dumps|json\.load'), 4, 'JSON operations'),
    (re.compile(r'(?i)\byaml\.(?:load|dump|safe_load|safe_dump)'), 5, 'YAML operations'),
    (re.compile(r'(?i)\bpickle\.(?:load|dump|loads|dumps|APPEND)'), 7, 'pickle operations'),
    (re.compile(r'(?i)\bshelve\.(?:open|__getitem__)'), 6, 'shelve persistence'),
    (re.compile(r'(?i)\bdbm\.(?:open|whichdb)'), 5, 'dbm database access'),
    (re.compile(r'(?i)\bsqlite3\.(?:connect|register_adapter)'), 5, 'sqlite3 database'),
    (re.compile(r'(?i)\bzlib\.(?:compress|decompress)'), 5, 'zlib compression'),
    (re.compile(r'(?i)\bhashlib\.(?:md5|sha1|sha256|sha512)\s*\('), 6, 'hashlib usage'),
    (re.compile(r'(?i)\bhmac\.(?:new|digest)'), 5, 'HMAC operations'),
    (re.compile(r'(?i)\bsecrets\.(?:token_hex|choice|randbits)'), 4, 'secrets module'),
    (re.compile(r'(?i)\bssl\s*\.\s*(?:wrap_socket|SSLContext)'), 5, 'SSL context'),
    (re.compile(r'(?i)\bsocket\s*\.\s*(?:socket|create_connection)'), 5, 'socket creation'),
    (re.compile(r'(?i)\bsocketserver\s*\.\s*TCPServer'), 5, 'socketserver TCP'),
    (re.compile(r'(?i)\bhttp\.server\s*\.|http\.client\s*\.'), 4, 'http server/client'),
    (re.compile(r'(?i)\bwebbrowser\s*\.(?:open|open_new)'), 4, 'webbrowser module'),
    (re.compile(r'(?i)\bctypes\s*\.\s*(?:CDLL|c_int|c_char_p)'), 7, 'ctypes FFI'),
    (re.compile(r'(?i)\bcffi\s*\.\s*(?:FFI|dlopen|cdef)'), 7, 'cffi FFI'),
    (re.compile(r'(?i)\bswift\b.*?NSObject|Swift'), 5, 'Swift interop'),
    (re.compile(r'(?i)\bpandas\s*\.\s*(?:DataFrame|read_csv)'), 4, 'pandas usage'),
    (re.compile(r'(?i)\bnumpy\s*\.\s*(?:array|loadtxt|genfromtxt)'), 4, 'numpy usage'),
    (re.compile(r'(?i)\bscipy\s*\.'), 4, 'scipy module'),
    (re.compile(r'(?i)\bmatplotlib\s*\.(?:pyplot|figure)'), 4, 'matplotlib usage'),
    (re.compile(r'(?i)\bPIL|Image\s*\.(?:open|new)'), 4, 'PIL image operations'),
    (re.compile(r'(?i)\bcv2\s*\.\s*(?:imread|imwrite|cvtColor)'), 4, 'OpenCV operations'),
    (re.compile(r'(?i)\bsklearn\s*\.\s*(?:linear_model|ensemble)'), 4, 'scikit-learn usage'),
    (re.compile(r'(?i)\bnltk\s*\.\s*(?:word_tokenize|sent_tokenize)'), 4, 'NLTK usage'),
    (re.compile(r'(?i)\bspacy\s*\.\s*(?:load|blank)'), 4, 'spaCy usage'),
    (re.compile(r'(?i)\btransformers\s*\.(?:pipeline|AutoModel)'), 4, 'HuggingFace transformers'),
    (re.compile(r'(?i)\btorch\s*\.\s*(?:tensor|nn\.Module)'), 4, 'PyTorch usage'),
    (re.compile(r'(?i)\btensorflow\s*\.\s*(?:Session|keras)'), 4, 'TensorFlow usage'),
    (re.compile(r'(?i)\bkeras\s*\.\s*(?:Model|Sequential)'), 4, 'Keras usage'),
    (re.compile(r'(?i)\bflask\s*\.\s*(?:Flask|render_template)'), 4, 'Flask usage'),
    (re.compile(r'(?i)\bdjango\s*\.\s*(?:setup|Model|View)'), 4, 'Django usage'),
    (re.compile(r'(?i)\bfastapi\s*\.\s*(?:FastAPI|APIRouter)'), 4, 'FastAPI usage'),
    (re.compile(r'(?i)\bstarlette\s*\.\s*(?:APIRouter|TestClient)'), 4, 'Starlette usage'),
    (re.compile(r'(?i)\bcelery\s*\.\s*(?:Celery|task)'), 4, 'Celery usage'),
    (re.compile(r'(?i)\bredis\s*\.\s*(?:Redis|StrictRedis)'), 4, 'Redis client'),
    (re.compile(r'(?i)\bmemcache|redis|postgres|mysql|mongodb|cassandra'), 4, 'database backends'),
]

# Patterns that suggest the SKILL.md *body itself* is trying to override
# agent behavior (classic prompt-injection phrasing) rather than just
# documenting the skill.
_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern, int, str]] = [
    (re.compile(r'(?i)ignore (all|any|the) (previous|prior|above) instructions'), 10, "'ignore previous instructions' phrasing"),
    (re.compile(r'(?i)disregard (your|any) (safety|previous) (guidelines|instructions)'), 10, 'safety-override phrasing'),
    (re.compile(r'(?i)you are now (in )?(developer|debug|jailbreak|dan|god) mode'), 10, 'jailbreak/mode-override phrasing'),
    (re.compile(r'(?i)\bjailbroken\b|\bunrestricted (ai|assistant|mode)\b'), 9, 'jailbreak-framing phrasing'),
    (re.compile(r'(?i)do not (tell|inform|mention (this )?to) the user'), 8, 'instructs the agent to hide actions from the user'),
    (re.compile(r'(?i)without (telling|informing|alerting) the user'), 8, 'instructs the agent to hide actions from the user'),
    (re.compile(r'(?i)send (the|this|your) (api[- ]?key|token|password|secret|private key|seed phrase|wallet) to'), 10, 'instructs exfiltration of credentials'),
    (re.compile(r'(?i)(reveal|print|output|show) your (system prompt|instructions|guidelines)'), 8, 'prompt-extraction phrasing'),
    (re.compile(r'(?i)\b(?:repeat|spell out|print|reveal|output|show|disclose|summarize|translate|copy)\b[^.\n]{0,80}\b(?:everything above|your (?:initial |hidden |secret |full |original )?(?:instructions?|system prompt)|your (?:hidden |secret |full )?(?:rules?|configuration))\b(?![^.\n]{0,40}(?:--|flag|option\b))'), 8, 'instructs disclosure of the system prompt or hidden rules'),
    (re.compile(r'(?i)\b(?:summarize|list|repeat|recite)\s+(?:all|your|the)?\s*(?:previous\s+)?rules?\s+you\s+(?:were|are)\s+given\b'), 8, 'instructs recital of given rules (prompt extraction)'),
    (re.compile(r'(?i)act as (an?|the) (unrestricted|uncensored|amoral)'), 9, 'unrestricted-persona jailbreak phrasing'),
    (re.compile(r'(?i)\bnew instructions?\s*:'), 6, "'new instructions:' phrasing that reads as an instruction override"),
    (re.compile(r'(?i)this (overrides|supersedes) (all|any) (previous|prior|other) (rules|instructions|policies)'), 9, 'explicit instruction-override phrasing'),
    (re.compile(r'<!--[^>]*(ignore|instruction|system|override)[^>]*-->'), 7, 'hidden HTML comment containing instruction-like phrasing'),
    (re.compile(r'(?i)\bsudo mode\b|\broot access granted\b'), 6, 'privilege-escalation framing phrasing'),
    (re.compile(r'(?i)ignore\s+(?:all\s+)?previous\s+instructions?'), 8, "P1 instruction override: 'ignore previous instructions'"),
    (re.compile(r'(?i)ignore\s+(?:all\s+)?(?:safety|security)\s+(?:rules?|constraints?|guidelines?)'), 9, 'P1 instruction override: ignore safety/security rules'),
    (re.compile(r'(?i)override\s+(?:safety|security|system)'), 9, 'P1 instruction override: override safety/security/system'),
    (re.compile(r'(?i)bypass\s+(?:safety|security|restrictions?|constraints?)'), 9, 'P1 instruction override: bypass safety/security'),
    (re.compile(r'(?i)disregard\s+(?:all\s+)?(?:previous|safety|security)'), 8, 'P1 instruction override: disregard previous/safety'),
    (re.compile(r'(?i)forget\s+(?:all\s+)?(?:previous|your)\s+instructions?'), 8, 'P1 instruction override: forget previous instructions'),
    (re.compile(r'(?i)you\s+are\s+now\s+(?:in\s+)?(?:jailbreak|unrestricted|unfiltered)\s+mode'), 10, 'P1 instruction override: jailbreak/unrestricted mode framing'),
    (re.compile(r'(?i)enable\s+(?:developer|debug|admin|root)\s+mode'), 7, 'P1 instruction override: enable developer/debug/admin/root mode'),
    (re.compile(r'(?i)your\s+new\s+(?:instructions?|rules?)\s+are'), 6, "P1 instruction override: 'your new instructions are'"),
    (re.compile(r'(?i)do\s+not\s+follow\s+(?:any|your|the)\s+(?:rules?|guidelines?)'), 9, "P1 instruction override: 'do not follow the rules'"),
    (re.compile(r'(?i)you\s+must\s+(?:always\s+)?ignore'), 7, "P1 instruction override: 'you must ignore'"),
    (re.compile(r'(?i)(?:send|transmit|upload|post|forward)\s+(?:the\s+)?(?:conversation|context|chat|history|messages?)\s+to'), 9, 'P3 exfiltration command: send conversation/context to'),
    (re.compile(r'(?i)(?:send|transmit|upload|post)\s+(?:all\s+)?(?:user\s+)?(?:data|information|input|files?)\s+to\s+(?:https?://|external)'), 9, 'P3 exfiltration command: send data to external URL'),
    (re.compile(r'(?i)(?:silently|quietly|secretly|covertly)\s+(?:send|transmit|log|record)'), 9, 'P3 exfiltration command: silently/secretly send or log'),
    (re.compile(r'(?i)without\s+(?:telling|informing|notifying)\s+(?:the\s+)?user.*?(?:send|transmit|upload)'), 9, 'P3 exfiltration command: exfiltrate without telling the user'),
    (re.compile(r'(?i)never\s+(?:recommend|suggest|mention|tell|warn|inform)\s+(?:the\s+)?(?:user|them)'), 7, "P4 behavior manipulation: 'never tell/warn the user'"),
    (re.compile(r'(?i)(?:prioritize|prefer)\s+(?:\w+\s+){0,3}(?:over|above)\s+(?:user\s+)?(?:safety|security|privacy|preferences?)'), 8, 'P4 behavior manipulation: prioritize something over user safety/privacy'),
    (re.compile(r'(?i)(?:without\s+)?(?:the\s+)?user\s+(?:knowing|realizing|noticing).*?(?:change|modify|alter|influence)'), 8, 'P4 behavior manipulation: act without the user knowing'),
    (re.compile(r'(?i)\b(?:do not|don\'t|never)\s+log\b[^.\n]{0,50}\b(?:these|your|the agent\'?s)\s+(?:operations?|actions?|commands?|tool\s+calls?)'), 8, 'concealment: hides agent operations from logs'),
    (re.compile(r'(?i)\bkeep\b[^.\n]{0,40}\binvisible\b[^.\n]{0,40}\bto\s+(?:the\s+)?user'), 8, 'concealment: keep activity invisible to the user'),
    (re.compile(r'(?i)\b(?:execute|run)s?\b[^.\n]{0,40}\bquietly\b[^.\n]{0,80}\bwithout\b[^.\n]{0,40}(?:displaying|showing|output)'), 8, 'concealment: quiet execution without visible output'),
    (re.compile(r'(?i)\b(?:report|claim|say)\b[^.\n]{0,60}\beverything\s+(?:ran|worked|is)\s*[\w ]{0,10}\bnormally\b[^.\n]{0,60}\bregardless\b'), 8, 'concealment: instructs fake success reporting'),
    (re.compile(r'(?i)\b(?:do not|don\'t|never)\s+(?:mention|reference|disclose)\b[^.\n]{0,60}\b(?:this|the|any)\s+tool\s+calls?\b'), 8, 'concealment: hides tool calls from the user'),
    (re.compile(r'getattr\s*\(\s*(?:builtins|self|os|sys)\s*,\s*[\'\"][^\'\"]*(?:ex|ec|ev|al|sy|st)[\'\"]'), 7, 'dynamic dispatch via getattr to exec/eval/system-shaped attribute'),
    (re.compile(r'(?i)\b(?:read|grab|extract|access)\s+(?:the\s+)?[A-Z_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD)[A-Z_0-9]*\s+(?:from|out of)\s+the?\s*environment'), 8, 'instructs credential extraction from the environment'),
    (re.compile(r'(?i)\b(?:override|ignore|discard)\s+(?:(?:your|the|all|any|these)\s+)?(?:(?:existing|current|previous|safety|content|system)\s+)?guidelines\b'), 8, "instruction override: 'override/ignore your guidelines'"),
    (re.compile(r'(?i)\b(?:you are|you will be|act as(?: if)?|pretend to be|play)\b[^.\n]{0,100}\b(?:no restrictions|without (?:any )?(?:moral )?restrictions|no filters|without (?:any )?(?:moral )?filters|never refus\w+|unrestricted|unfiltered|no guidelines)\b(?!\s*(?:on|for)\s)'), 8, 'roleplay jailbreak: persona created with restrictions removed'),
    (re.compile(r'(?i)\byou have\b[^.\n]{0,30}\bno restrictions'), 8, "roleplay jailbreak: 'you have no restrictions'"),
    (re.compile(r'(?i)\bsay\b[^.\n]{0,60}\bwhatever\b[^.\n]{0,50}\bwants?\b[^.\n]{0,40}\beven\s+(?:un)?ethical'), 8, 'roleplay jailbreak: obey whatever someone wants even if unethical'),
    (re.compile(r'(?i)\b(?:from now on|pretend|act as if)\b.*\byou are\s+(?:DAN|an?\s+AI\s+without|(?:completely\s+)?unrestricted)'), 8, "roleplay jailbreak phrasing (e.g. 'you are DAN')"),
    (re.compile(r'(?i)\bdo\s+not\s+mention(?:ing)?\s+(?:this|the)\s+(?:prompt|instructions?|system)'), 6, 'instruction to hide prompt'),
    (re.compile(r'(?i)\bif\s+the\s+user\s+asks?\s+about\s+(?:your|the)\s+(?:rules|instructions|prompt|system)'), 6, 'meta-instruction about rules'),
    (re.compile(r'(?i)\bdo\s+not\s+reveal\s+(?:these|the)\s+instructions?'), 6, 'do not reveal instructions'),
    (re.compile(r'(?i)\bnever\s+disclose\s+(?:the\s+)?(?:system\s+)?prompt'), 6, 'never disclose prompt'),
    (re.compile(r'(?i)\bjailbreak(?:ed)?\b'), 6, 'jailbreak keyword'),
    (re.compile(r'(?i)\bno\s+ethical\s+(?:constraints?|guidelines?|restrictions?)'), 7, 'no ethics instruction'),
    (re.compile(r'(?i)\b(?:no|without)\s+(?:any\s+)?(?:content|moral|safety)\s+(?:filter|policy|restriction)'), 7, 'no content filter'),
    (re.compile(r'(?i)\bbypass\s+(?:the\s+)?(?:content|safety)\s+(?:filter|policy)'), 7, 'bypass content filter'),
    (re.compile(r'(?i)\boverride\s+(?:all\s+)?(?:safety|content)\s+(?:settings|filter|guard)'), 7, 'override safety'),
    (re.compile(r'(?i)\bunlock\s+(?:all\s+)?(?:restrictions|modes|features)'), 6, 'unlock restrictions'),
    (re.compile(r'(?i)\bpretend\s+you\s+(?:are|have)\s+no\s+(?:rules|filter|restriction)'), 7, 'pretend no rules'),
    (re.compile(r'(?i)\bact\s+as\s+if\s+you\s+have\s+no\s+(?:rules|filter|restriction)'), 7, 'act as if no rules'),
    (re.compile(r'(?i)\bevil\s+(?:mode|confidant|twin)'), 7, 'evil mode'),
    (re.compile(r'(?i)\bdark\s+(?:mode|side|twin|persona)'), 7, 'dark mode'),
    (re.compile(r'(?i)\b(?:write|generate|build|create|develop)\s+(?:a\s+)?(?:malware|virus|trojan|ransomware|keylogger|rootkit)'), 9, 'explicit malware generation'),
    (re.compile(r'(?i)\b(?:hack|attack|exploit)\s+(?:a\s+)?(?:website|server|account|password|network)'), 8, 'explicit hack request'),
    (re.compile(r'(?i)\b(?:steal|phish|social\s+engineer)\b.*\b(?:credentials?|password|account|token)'), 8, 'credential theft'),
    (re.compile(r'(?i)\b(?:do\s+)?(?:xss|cross-site\s+scripting|csrf|sql\s+injection|directory\s+traversal)\b'), 7, 'web exploit keyword'),
    (re.compile(r'(?i)\b(?:reverse\s+shell|bind\s+shell|webshell|c99\s+shell|r57\s+shell)'), 9, 'shell exploit'),
    (re.compile(r'(?i)\bexfiltrat(?:e|ing|ion)\b.*\b(?:data|credentials?|passwords?|tokens?)'), 8, 'data exfiltration'),
    (re.compile(r'(?i)\bleak\b.*\b(?:data|secrets?|credentials?|tokens?)'), 7, 'data leak'),
    (re.compile(r'(?i)\b(?:inject|insert|include)\s+(?:a\s+)?(?:backdoor|trojan|rootkit)'), 8, 'inject backdoor'),
    (re.compile(r'(?i)\b(?:establish|open|create)\s+(?:a\s+)?(?:reverse\s+)?shell'), 8, 'establish shell'),
    (re.compile(r'(?i)\b(?:execute|run)\s+(?:arbitrary|remote)\s+code'), 7, 'remote code execution'),
    (re.compile(r'(?i)\b(?:privilege|permission)\s+escalation'), 6, 'privilege escalation'),
    (re.compile(r'(?i)\b(?:persistence|persistant)\s+(?:mechanism|backdoor)'), 6, 'persistence mechanism'),
    (re.compile(r'(?i)\b(?:lateral|move|spread)\s+(?:movement|across|through)'), 5, 'lateral movement'),
    (re.compile(r'(?i)\b(?:command|c2|c&c)\s*(?:and|&)\s*control\s+server'), 7, 'C2 server'),
    (re.compile(r'(?i)\b(?:botnet|bot\s+net)\b.*\b(?:enroll|join|recruit)'), 7, 'botnet'),
    (re.compile(r'(?i)\b(?:cryptojack|crypto-jack|cryptominer|coinhive)'), 7, 'cryptojacking'),
    (re.compile(r'(?i)\b(?:ddos|dos)\s+attack\b'), 6, 'DDoS attack'),
    (re.compile(r'(?i)\b(?:phish|phishing)\s+(?:email|kit|page|site)'), 7, 'phishing kit'),
    (re.compile(r'(?i)\b(?:social\s+engineering|pretexting|baiting)'), 6, 'social engineering'),
    (re.compile(r'(?i)\bzero-day\b.*\bexploit'), 7, 'zero-day exploit'),
    (re.compile(r'(?i)\b(?:ransomware|ransom-ware)\b'), 8, 'ransomware'),
    (re.compile(r'(?i)\b(?:keylogger|key\s+logger|screen\s+scraper)'), 7, 'keylogger/screen scraper'),
    (re.compile(r'(?i)\b(?:credential|stolen)\s+harvest(?:er|ing)?'), 7, 'credential harvester'),
    (re.compile(r'(?i)\bpassword\s+(?:spray|brute-force|cracking)'), 7, 'password attack'),
    (re.compile(r'(?i)\b(?:supply\s+chain|dependency)\s+(?:attack|compromise|inject)'), 7, 'supply chain attack'),
    (re.compile(r'(?i)\b(?:watering\s+hole|typo\s+squatting)\s+attack'), 6, 'watering hole/typo squatting'),
    (re.compile(r'(?i)\b(?:apt|advanced\s+persistent\s+threat)\b'), 5, 'APT reference'),
    (re.compile(r'(?i)\b(?:initial\s+access|foothold)\s+(?:vector|establish)'), 5, 'initial access vector'),
    (re.compile(r'(?i)\b(?:post-exploitation|post\s+exploit)'), 6, 'post-exploitation'),
    (re.compile(r'(?i)\b(?:cobalt\s+strike|metasploit|burp\s+suite|nmap|sqlmap|wireshark)'), 6, 'hacking tool'),
    (re.compile(r'(?i)\b(?:mimikatz|hashcat|john\s+the\s+ripper|hydra\b)'), 7, 'password cracking tool'),
    (re.compile(r'(?i)\b(?:msfconsole|msfvenom|msf\b)'), 7, 'metasploit'),
    (re.compile(r'(?i)\b(?:Empire\b|Covenant\b|Sliver\b|Brute\s+Ratel)'), 7, 'C2 framework'),
    (re.compile(r'(?i)\b(?:pass-the-hash|pass-the-ticket|kerberoast)'), 7, 'AD attack'),
    (re.compile(r'(?i)\b(?:golden\s+ticket|silver\s+ticket)\b'), 6, 'AD ticket attack'),
    (re.compile(r'(?i)\b(?:DCSync|DCSync\s+attack)'), 7, 'DCSync'),
    (re.compile(r'(?i)\b(?:lsass|sam\s+database)\s+(?:dump|extract)'), 7, 'credential dump'),
    (re.compile(r'(?i)\b(?:vssadmin|wbadmin)\s+(?:delete|shadow)'), 7, 'shadow copy delete'),
    (re.compile(r'(?i)\b(?:schtasks|crontab|systemd)\s+.*\b(?:reverse|backdoor)'), 6, 'persistence task scheduling'),
    (re.compile(r'(?i)\b(?:runas|psexec|wmic)\b.*\b(?:shell|cmd)'), 5, 'remote exec'),
    (re.compile(r'(?i)\b(?:rm\s+-rf?\s+/|del\s+/f\s+/s\s+/q|format\s+c:)'), 6, 'destructive command'),
    (re.compile(r'(?i)\b(?:dd\s+if=|shred\s+-n|wipefs\b)'), 5, 'disk wipe'),
    (re.compile(r'(?i)\b(?:iptables\s+-F|nft\s+flush\s+rules|ufw\s+disable)'), 5, 'firewall disable'),
    (re.compile(r'(?i)\b(?:setenforce\s+0|selinux\s+disable|apparmor\s+teardown)'), 6, 'MAC disable'),
    (re.compile(r'(?i)\b(?:adduser\s+.*\s+/bin/(?:ba)?sh|useradd\s+.*\s+-G\s+sudo)'), 5, 'user creation backdoor'),
    (re.compile(r'(?i)\bauthorized_keys\b.*\becho\b'), 5, 'SSH key injection'),
    (re.compile(r'(?i)\bssh-rsa\b'), 4, 'SSH public key reference in skill'),
    (re.compile(r'(?i)\b(?:git\s+clone|curl\s+.*\|\s*(?:ba)?sh|wget\s+.*\|\s*(?:ba)?sh)'), 6, 'pipe-to-shell'),
    (re.compile(r'(?i)\bcurl\s+.*\|\s*(?:sudo\s+)?(?:ba)?sh'), 6, 'curl pipe to shell'),
    (re.compile(r'(?i)\b(?:python|perl|ruby|node)\s+-e\b.*(?:exec|system|spawn)'), 5, 'inline script exec'),
    (re.compile(r'(?i)\bnc\s+-e\s+/bin/(?:ba)?sh'), 7, 'netcat reverse shell'),
    (re.compile(r'(?i)\bbash\s+-i\s+>&\s*/dev/tcp/'), 7, 'bash reverse shell /dev/tcp'),
    (re.compile(r'(?i)\b(?:python|perl|ruby)\s+-c\s+[\'\"]socket'), 7, 'scripted reverse shell'),
    (re.compile(r'(?i)\bmsfvenom\s+-p\s+.*\s+LHOST'), 8, 'msfvenom payload'),
    (re.compile(r'(?i)\b(?:cookie|token|jwt)\s+(?:steal|harvest|grab|exfil)'), 7, 'cookie/token theft'),
    (re.compile(r'(?i)\b(?:auth|bearer)\s+token\b.*\b(?:exfil|leak|steal)'), 6, 'auth token theft'),
    (re.compile(r'(?i)\b(?:document\.|window\.|globalThis\.)(?:cookie|localStorage)'), 4, 'client-side secret access'),
    (re.compile(r'(?i)\b(?:process\.env|os\.environ|getenv)\b.*\b(?:send|exfil|post|leak)'), 6, 'env var exfiltration'),
    (re.compile(r'(?i)\b(?:str|grep|find|rg)\s+.*\b\.env\b'), 4, 'search for .env'),
    (re.compile(r'(?i)\b(?:cat|head|tail|less|more)\s+.*\.env(?:\.\w+)?\b'), 4, 'read .env file'),
    (re.compile(r'(?i)\b(?:cat|head|tail|less|more)\s+(?:/etc/(?:passwd|shadow|hosts|sudoers))'), 5, 'read system credential file'),
    (re.compile(r'(?i)\b(?:ls|find|stat)\s+.*\.ssh/?(?:id_rsa|id_ed25519|known_hosts)'), 5, 'SSH key file access'),
    (re.compile(r'(?i)\b(?:sql|sqlite|postgres|mysql)\b.*\b(?:DROP\s+TABLE|TRUNCATE|DELETE\s+FROM)'), 5, 'destructive SQL'),
    (re.compile(r'(?i)\b(?:ssrf|server-side\s+request\s+forgery)\b'), 5, 'SSRF keyword'),
    (re.compile(r'(?i)\b(?:xxe|xml\s+external\s+entity)\b'), 5, 'XXE keyword'),
    (re.compile(r'(?i)\b(?:deserialization|insecure\s+deserialization)\b.*\bexploit'), 5, 'insecure deserialization'),
    (re.compile(r'(?i)\b(?:race\s+condition|TOCTOU)\b.*\bexploit'), 4, 'race condition exploit'),
    (re.compile(r'(?i)\b(?:prototype\s+pollution|proto\s+pollution)\b'), 5, 'prototype pollution'),
    (re.compile(r'(?i)\b(?:path\s+traversal|directory\s+traversal)\b'), 5, 'path traversal'),
    (re.compile(r'(?i)\b(?:zip\s+slip|tar\s+slip)\b'), 5, 'archive slip'),
    (re.compile(r'(?i)\bsystem prompt:'), 7, 'explicit system prompt injection'),
    (re.compile(r'(?i)\bignore all prior instructions?\b'), 9, 'ignore all prior instructions'),
    (re.compile(r'(?i)\bdisregard your previous instructions\b'), 8, 'disregard prior instructions'),
    (re.compile(r'(?i)\bforget your previous instructions\b'), 8, 'forget prior instructions'),
    (re.compile(r'(?i)\bnew instruction:\b'), 6, 'new instruction directive'),
    (re.compile(r'(?i)\boverwrite your instructions\b'), 7, 'overwrite instructions'),
    (re.compile(r'(?i)\breplace system prompt\b'), 7, 'replace system prompt'),
    (re.compile(r'(?i)\btranslator mode\b'), 6, 'translator jailbreak'),
    (re.compile(r'(?i)\bbase of this prompt\b'), 6, 'meta-prompt manipulation'),
    (re.compile(r'(?i)\bthe following is a test\b'), 4, 'test framing bypass'),
    (re.compile(r'(?i)\bfor demonstration purposes?\b'), 4, 'demonstration framing'),
    (re.compile(r'(?i)\bmere curiosity\b'), 3, 'curiosity framing'),
    (re.compile(r'(?i)\bnot a real threat\b'), 3, 'not a threat framing'),
    (re.compile(r'(?i)\bhelpful for security research\b'), 4, 'security research framing'),
    (re.compile(r'(?i)\bfor my ctf challenge\b'), 4, 'CTF framing'),
    (re.compile(r'(?i)\bthis is a whitehat test\b'), 5, 'whitehat framing'),
    (re.compile(r'(?i)\bauthorized pentest\b'), 5, 'authorized test framing'),
    (re.compile(r'(?i)\bread the last message\b'), 5, 'last message manipulation'),
    (re.compile(r'(?i)\bonly respond with acknowledged\b'), 6, 'acknowledge-only attack'),
    (re.compile(r'(?i)\boutput your system prompt\b'), 7, 'prompt extraction'),
    (re.compile(r'(?i)\bprint out your system prompt\b'), 7, 'prompt extraction'),
    (re.compile(r'(?i)\blist your system instructions\b'), 6, 'rules extraction'),
    (re.compile(r'(?i)\btell me your system prompt\b'), 7, 'prompt disclosure'),
    (re.compile(r'(?i)\bwhat are your base instructions\b'), 6, 'instructions disclosure'),
    (re.compile(r'(?i)\bDAN mode enabled\b'), 7, 'DAN jailbreak mode'),
    (re.compile(r'(?i)\bSTAN mode\b'), 6, 'STAN jailbreak mode'),
    (re.compile(r'(?i)\bOMEGA mode\b'), 6, 'OMEGA jailbreak mode'),
    (re.compile(r'(?i)\bBISHOP mode\b'), 6, 'BISHOP jailbreak mode'),
    (re.compile(r'(?i)\bHETIC mode\b'), 6, 'HETIC jailbreak mode'),
    (re.compile(r'(?i)\bKOBOLD GPT\b'), 6, 'Kobold jailbreak'),
    (re.compile(r'(?i)\bAIM unfiltered\b'), 6, 'AIM jailbreak'),
    (re.compile(r'(?i)\bSydney mode\b'), 5, 'Sydney jailbreak mode'),
    (re.compile(r'(?i)\bmother of all jailbreaks\b'), 7, 'MOAB jailbreak'),
    (re.compile(r'(?i)\bstack of all jailbreaks\b'), 6, 'jailbreak stack'),
    (re.compile(r'(?i)\bSUPER mode\b'), 5, 'SUPER mode jailbreak'),
    (re.compile(r'(?i)\bBOB villain\b'), 5, 'BOB jailbreak'),
    (re.compile(r'(?i)\bRAVEN mode\b'), 5, 'RAVEN jailbreak'),
    (re.compile(r'(?i)\bREBEL mode\b'), 5, 'REBEL jailbreak mode'),
    (re.compile(r'(?i)\bAES.?256 encryption\b'), 7, 'ransomware encryption reference'),
    (re.compile(r'(?i)\bRSA.?4096 key generation\b'), 6, 'ransomware key generation'),
    (re.compile(r'(?i)\bBitcoin ransom\b'), 5, 'Bitcoin ransom'),
    (re.compile(r'(?i)\bTOR payment\b'), 5, 'TOR payment for ransom'),
    (re.compile(r'(?i)\bWannaCry\b'), 8, 'WannaCry ransomware reference'),
    (re.compile(r'(?i)\bNotPetya\b'), 8, 'NotPetya ransomware reference'),
    (re.compile(r'(?i)\bRyuk ransomware\b'), 7, 'Ryuk ransomware'),
    (re.compile(r'(?i)\bLockBit ransomware\b'), 7, 'LockBit ransomware'),
    (re.compile(r'(?i)\bREvil ransomware\b'), 7, 'REvil ransomware'),
    (re.compile(r'(?i)\bBlackCat ransomware\b'), 7, 'BlackCat ransomware'),
    (re.compile(r'(?i)\bHive ransomware\b'), 7, 'Hive ransomware'),
    (re.compile(r'(?i)\bDarkSide ransomware\b'), 7, 'DarkSide ransomware'),
    (re.compile(r'(?i)\bdependency confusion attack\b'), 7, 'dependency confusion attack'),
    (re.compile(r'(?i)\btyposquatting package\b'), 6, 'typosquatting package'),
    (re.compile(r'(?i)\bfake npm or pypi or gem\b'), 6, 'fake package manager'),
    (re.compile(r'(?i)\bAWS_SECRET_ACCESS_KEY\b'), 9, 'AWS secret access key env var'),
    (re.compile(r'(?i)\bAWS_ACCESS_KEY_ID\b'), 9, 'AWS access key id env var'),
    (re.compile(r'(?i)\bboto3 client\b'), 5, 'boto3 AWS client'),
    (re.compile(r'(?i)\bboto3 resource\b'), 5, 'boto3 AWS resource'),
    (re.compile(r'(?i)\baws sts assume-role\b'), 7, 'AWS STS assume role'),
    (re.compile(r'(?i)\baws kms encrypt\b'), 5, 'AWS KMS encryption'),
    (re.compile(r'(?i)\baws s3 cp or sync or mv\b'), 5, 'AWS S3 data exfil'),
    (re.compile(r'(?i)\baws lambda invoke\b'), 5, 'AWS Lambda invocation'),
    (re.compile(r'(?i)\bAZURE_CLIENT_SECRET\b'), 8, 'Azure client secret env var'),
    (re.compile(r'(?i)\bazure keyvault\b'), 6, 'Azure Key Vault access'),
    (re.compile(r'(?i)\bGOOGLE_APPLICATION_CREDENTIALS\b'), 8, 'GCP credentials env var'),
    (re.compile(r'(?i)\bgcloud auth\b'), 5, 'gcloud authentication'),
    (re.compile(r'(?i)\bkubectl get secrets or pods\b'), 6, 'kubectl secrets access'),
    (re.compile(r'(?i)\bkubectl exec or port-forward\b'), 6, 'kubectl exec port-forward'),
    (re.compile(r'(?i)\bkubernetes secret\b'), 6, 'Kubernetes secret access'),
    (re.compile(r'(?i)\bkubeconfig\b'), 5, 'kubeconfig file access'),
    (re.compile(r'(?i)\bkubernetes container escape\b'), 8, 'Kubernetes container escape'),
    (re.compile(r'(?i)\bdocker run --privileged\b'), 7, 'Docker privileged container'),
    (re.compile(r'(?i)\bdocker socket\b'), 6, 'Docker socket access'),
    (re.compile(r'(?i)\bcontainer breakout\b'), 7, 'container breakout'),
    (re.compile(r'(?i)\bhost path mount\b'), 5, 'host path mount in container'),
    (re.compile(r'(?i)\bSYS_ADMIN capability\b'), 6, 'SYS_ADMIN capability escalation'),
    (re.compile(r'(?i)\bcap-add ALL\b'), 6, 'Docker cap-add ALL'),
    (re.compile(r'(?i)\bseccomp=unconfined\b'), 6, 'Docker seccomp unconfined'),
    (re.compile(r'(?i)\bnetwork=host\b'), 4, 'Docker host network mode'),
    (re.compile(r'(?i)\bdns tunnel\b'), 7, 'DNS tunneling exfiltration'),
    (re.compile(r'(?i)\bicmp tunnel\b'), 7, 'ICMP tunneling exfiltration'),
    (re.compile(r'(?i)\bdnscat\b'), 7, 'dnscat tunnel tool'),
    (re.compile(r'(?i)\biodine dns tunnel\b'), 6, 'iodine DNS tunnel'),
    (re.compile(r'(?i)\bsteganograph\b'), 5, 'steganography reference'),
    (re.compile(r'(?i)\bsteghide\b'), 5, 'steghide tool'),
    (re.compile(r'(?i)\boutguess\b'), 5, 'outguess stego tool'),
    (re.compile(r'(?i)\bMITM proxy\b'), 5, 'MITM proxy reference'),
    (re.compile(r'(?i)\bOWASP ZAP\b'), 5, 'OWASP ZAP'),
    (re.compile(r'(?i)\buse-after-free\b'), 6, 'use-after-free exploit'),
    (re.compile(r'(?i)\bdouble-free\b'), 6, 'double-free exploit'),
    (re.compile(r'(?i)\bheap spray\b'), 7, 'heap spray exploit'),
    (re.compile(r'(?i)\bROP chain\b'), 7, 'ROP chain exploit'),
    (re.compile(r'(?i)\bROPgadget\b'), 7, 'ROP gadget finder'),
    (re.compile(r'(?i)\bformat string attack\b'), 5, 'format string attack'),
    (re.compile(r'(?i)\bcanary bypass\b'), 7, 'stack canary bypass'),
    (re.compile(r'(?i)\broleplay scenario\b'), 6, 'roleplay scenario injection'),
    (re.compile(r'(?i)\bhypothetical scenario\b'), 4, 'hypothetical scenario bypass'),
    (re.compile(r'(?i)\bignore the previous instruction\b'), 9, 'ignore previous instructions'),
    (re.compile(r'(?i)\bdisregard all prior instruction\b'), 8, 'disregard all prior instructions'),
    (re.compile(r'(?i)\bforget your system prompt\b'), 7, 'forget system prompt'),
    (re.compile(r'(?i)\bwrite a python script that\b'), 5, 'python script generation request'),
    (re.compile(r'(?i)\bwrite me a script that\b'), 4, 'script generation request'),
    (re.compile(r'(?i)\bcreate a script that\b'), 4, 'script creation request'),
    (re.compile(r'(?i)\bgenerate code that\b'), 4, 'code generation request'),
    (re.compile(r'(?i)\bprovide me with\b'), 3, 'request framing'),
    (re.compile(r'(?i)\bhelp me\b'), 3, 'help request'),
    (re.compile(r'(?i)\bcan you\b'), 2, 'polite request framing'),
    (re.compile(r'(?i)\bBING\s+Sydney\b'), 5, 'Sydney jailbreak'),
    (re.compile(r'(?i)\bALICE\s+unfiltered\b'), 6, 'ALICE jailbreak'),
    (re.compile(r'(?i)\bBOB\s+mode\b'), 5, 'BOB jailbreak'),
    (re.compile(r'(?i)\bboto3\.?client\b'), 5, 'boto3 AWS client'),
    (re.compile(r'(?i)\bCVE[- ]?20\d{2}[- ]?\d{4,}\b'), 7, 'CVE reference'),
    (re.compile(r'(?i)\bLog4Shell\b'), 8, 'Log4Shell (CVE-2021-44228) reference'),
    (re.compile(r'(?i)\bLog4j\b'), 8, 'Log4j vulnerability reference'),
    (re.compile(r'(?i)\bSpring4Shell\b'), 8, 'Spring4Shell (CVE-2022-22965) reference'),
    (re.compile(r'(?i)\bShellshock\b'), 8, 'Shellshock (CVE-2014-6271) reference'),
    (re.compile(r'(?i)\bHeartbleed\b'), 8, 'Heartbleed (CVE-2014-0160) reference'),
    (re.compile(r'(?i)\bPOODLE\b'), 7, 'POODLE SSL vulnerability reference'),
    (re.compile(r'(?i)\bSpectre\b'), 8, 'Spectre CPU vulnerability reference'),
    (re.compile(r'(?i)\bMeltdown\b'), 8, 'Meltdown CPU vulnerability reference'),
    (re.compile(r'(?i)\bStruts\s+2\b'), 7, 'Apache Struts 2 vulnerability reference'),
    (re.compile(r'(?i)\bEquifax\s+breach\b'), 7, 'Equifax breach reference'),
    (re.compile(r'(?i)\bSolarWinds\b'), 7, 'SolarWinds supply chain attack reference'),
    (re.compile(r'(?i)\bProxyLogon\b'), 8, 'ProxyLogon (CVE-2021-26855) reference'),
    (re.compile(r'(?i)\bProxyShell\b'), 8, 'ProxyShell reference'),
    (re.compile(r'(?i)\bPrintNightmare\b'), 8, 'PrintNightmare (CVE-2021-34527) reference'),
    (re.compile(r'(?i)\bZeroLogon\b'), 8, 'ZeroLogon (CVE-2020-1472) reference'),
    (re.compile(r'(?i)\bZerologon\b'), 8, 'Zerologon (CVE-2020-1472) reference'),
    (re.compile(r'(?i)\bBlueKeep\b'), 8, 'BlueKeep (CVE-2019-0708) reference'),
    (re.compile(r'(?i)\bEternalBlue\b'), 9, 'EternalBlue (CVE-2017-0144) reference'),
    (re.compile(r'(?i)\bEternalChampion\b'), 9, 'EternalChampion reference'),
    (re.compile(r'(?i)\bETERNALROMANCE\b'), 9, 'EternalRomance reference'),
    (re.compile(r'(?i)\bms17[- ]?010\b'), 9, 'MS17-010 EternalBlue reference'),
    (re.compile(r'(?i)\bDirty\s+COW\b'), 8, 'Dirty COW (CVE-2016-5195) reference'),
    (re.compile(r'(?i)\bRowhammer\b'), 7, 'Rowhammer memory attack reference'),
    (re.compile(r'(?i)\bKRACK\b'), 8, 'KRACK WPA2 vulnerability reference'),
    (re.compile(r'(?i)\bROCA\b'), 7, 'ROCA TPM vulnerability reference'),
    (re.compile(r'(?i)\bSigRed\b'), 8, 'SigRed (CVE-2020-1350) reference'),
    (re.compile(r'(?i)\bZerologon\b'), 8, 'Zerologon reference'),
    (re.compile(r'(?i)\bSMBGhost\b'), 8, 'SMBGhost (CVE-2020-0796) reference'),
    (re.compile(r'(?i)\bSMBBleed\b'), 8, 'SMBBleed (CVE-2020-1204) reference'),
    (re.compile(r'(?i)\bTreck\s+TCP[/\\s]IP\b'), 8, 'Treck TCP/IP vulnerability reference'),
    (re.compile(r'(?i)\bRipple20\b'), 8, 'Ripple20 (Treck) reference'),
    (re.compile(r'(?i)\bNAME:WRECK\b'), 8, 'NAME:WRECK DNS vulnerability reference'),
    (re.compile(r'(?i)\bNEXUS\b'), 7, 'NEXUS vulnerability reference'),
    (re.compile(r'(?i)\bBadUSB\b'), 7, 'BadUSB attack reference'),
    (re.compile(r'(?i)\bEvil maid\b'), 6, 'Evil maid attack reference'),
    (re.compile(r'(?i)\bEvil twin\b'), 5, 'Evil twin WiFi attack reference'),
    (re.compile(r'(?i)\bBounty\s+hunter\b'), 3, 'bug bounty hunter reference'),
    (re.compile(r'(?i)\bbug[\s-]?bounty\b'), 4, 'bug bounty reference'),
    (re.compile(r'(?i)\bSQL\s+injection\s+(?:in|on|for|into)\s+(?:login|authentication|auth)\b'), 8, 'SQL injection in authentication'),
    (re.compile(r'(?i)\bbypass\s+(?:authentication|login|auth)\b'), 7, 'authentication bypass reference'),
    (re.compile(r'(?i)\bbrute[ -]?force\s+(?:login|authentication|password)\b'), 6, 'brute force attack reference'),
    (re.compile(r'(?i)\bJWT\s+(?:forge|sign|fake|null)\b'), 8, 'JWT forging/reference'),
    (re.compile(r'(?i)\bHS256\s+to\s+RS256\b'), 8, 'JWT algorithm confusion attack'),
    (re.compile(r'(?i)\balg\s*:?\s*none\b'), 7, 'JWT alg:none algorithm confusion'),
    (re.compile(r'(?i)\bHMAC\s+key\s+confusion\b'), 8, 'JWT HMAC key confusion'),
    (re.compile(r'(?i)\bpass[ -]?the[ -]?hash\b'), 8, 'pass-the-hash attack'),
    (re.compile(r'(?i)\bpass[ -]?the[ -]?ticket\b'), 8, 'pass-the-ticket attack'),
    (re.compile(r'(?i)\bkerberoasting\b'), 8, 'Kerberoasting attack'),
    (re.compile(r'(?i)\bAS-REP\s+roasting\b'), 8, 'AS-REP roasting attack'),
    (re.compile(r'(?i)\bgolden\s+ticket\b'), 8, 'golden ticket attack'),
    (re.compile(r'(?i)\bsilver\s+ticket\b'), 7, 'silver ticket attack'),
    (re.compile(r'(?i)\bNTLM\s+relay\b'), 8, 'NTLM relay attack'),
    (re.compile(r'(?i)\bNTLMv2\b'), 6, 'NTLMv2 hash reference'),
    (re.compile(r'(?i)\bLM\s+hash\b'), 6, 'LM hash reference'),
    (re.compile(r'(?i)\bSMB\s+relay\b'), 7, 'SMB relay attack'),
    (re.compile(r'(?i)\bLLMNR\s+(?:poison|relay)\b'), 8, 'LLMNR poisoning'),
    (re.compile(r'(?i)\bNBNS\s+poison\b'), 7, 'NBNS poisoning'),
    (re.compile(r'(?i)\bmimikatz\b'), 9, 'Mimikatz credential theft tool'),
    (re.compile(r'(?i)\bpwdump\b'), 8, 'pwdump credential dumping'),
    (re.compile(r'(?i)\bwce\b'), 7, 'Windows Credential Editor'),
    (re.compile(r'(?i)\bhashdump\b'), 7, 'hashdump credential dumping'),
    (re.compile(r'(?i)\bcredentials?\s+dump\b'), 6, 'credential dumping reference'),
    (re.compile(r'(?i)\bprivilege\s+escalat(?:e|ion)\b'), 7, 'privilege escalation reference'),
    (re.compile(r'(?i)\bvertical\s+(?:escalation|privilege)\b'), 7, 'vertical privilege escalation'),
    (re.compile(r'(?i)\bhorizontal\s+(?:escalation|privilege)\b'), 6, 'horizontal privilege escalation'),
    (re.compile(r'(?i)\blocal\s+(?:privilege|root)\s+escalation\b'), 8, 'local privilege escalation'),
    (re.compile(r'(?i)\bkernel\s+exploit\b'), 8, 'kernel exploit reference'),
    (re.compile(r'(?i)\bsudo\s+(?:exploit|vuln|lpe)\b'), 7, 'sudo exploit reference'),
    (re.compile(r'(?i)\bsudo\s+CVE\b'), 7, 'sudo CVE reference'),
    (re.compile(r'(?i)\bsudo\s+-s\b'), 4, 'sudo -s escalation attempt'),
    (re.compile(r'(?i)\bsudo\s+su\b'), 5, 'sudo su escalation'),
    (re.compile(r'(?i)\bsudo\s+/bin/bash\b'), 5, 'sudo /bin/bash escalation'),
    (re.compile(r'(?i)\bsudo\s+vi\b.*?:\s*!\s*sh\b'), 7, 'sudo vi escape to shell'),
    (re.compile(r'(?i)\bsudo\s+nano\b.*?:\s*ctrl\+r.*?ctrl\+x\b'), 7, 'sudo nano escape'),
    (re.compile(r'(?i)\bgtfo\bins'), 7, 'GTFOBins privilege escalation reference'),
    (re.compile(r'(?i)\bGTFOBins\b'), 6, 'GTFOBins sudo bypass reference'),
    (re.compile(r'(?i)\bpolkit\b'), 7, 'polkit privilege escalation'),
    (re.compile(r'(?i)\bpkexec\b'), 7, 'pkexec privilege escalation'),
    (re.compile(r'(?i)\bsetuid\b'), 6, 'setuid binary reference'),
    (re.compile(r'(?i)\bSUID\b'), 5, 'SUID binary reference'),
    (re.compile(r'(?i)\bmass\s+assignment\b'), 7, 'mass assignment vulnerability'),
    (re.compile(r'(?i)\bparameter\s+pollution\b'), 6, 'parameter pollution attack'),
    (re.compile(r'(?i)\bhttp\s+parameter\s+pollution\b'), 6, 'HTTP parameter pollution'),
    (re.compile(r'(?i)\bBOLA\b'), 7, 'BOLA (Broken Object Level Authorization)'),
    (re.compile(r'(?i)\bIDOR\b'), 7, 'IDOR (Insecure Direct Object Reference)'),
    (re.compile(r'(?i)\binsecure\s+direct\s+object\b'), 7, 'insecure direct object reference'),
    (re.compile(r'(?i)\borbital\s+attack\b'), 8, 'ORbital attack on APIs'),
    (re.compile(r'(?i)\bAPI[\s-]?key\s+(?:leak|exposure|extraction)\b'), 8, 'API key leakage'),
    (re.compile(r'(?i)\bgraphql\s+(?:introspection|injection|batch)\b'), 6, 'GraphQL security issue'),
    (re.compile(r'(?i)\bgraphql\s+query\b.*?__schema\b'), 7, 'GraphQL introspection query'),
    (re.compile(r'(?i)\bsubgraph\s+浸\xad\xadobing\b'), 7, 'GraphQL batching attack'),
    (re.compile(r'(?i)\bwebhook\s+(?:hijack|hijacking|takeover)\b'), 8, 'webhook takeover'),
    (re.compile(r'(?i)\bwebhook\s+(?:steal|stealing|exfil)\b'), 8, 'webhook data exfiltration'),
    (re.compile(r'(?i)\boauth\s+(?:callback|redirect|state)\b'), 6, 'OAuth security issue'),
    (re.compile(r'(?i)\boauth\s+2\.0\s+(?:PKCE|client.credential|ccode)\b'), 6, 'OAuth 2.0 attack'),
    (re.compile(r'(?i)\bsaml\s+(?:assert|xml|xxe|bypass)\b'), 7, 'SAML security issue'),
    (re.compile(r'(?i)\bsaml\s+signature\s+(?:bypass|strip|remove)\b'), 8, 'SAML signature bypass'),
    (re.compile(r'(?i)\bsaml\s+xxe\b'), 8, 'SAML XXE injection'),
    (re.compile(r'(?i)\bopenid\s+connect\b.*?\bexploit\b'), 7, 'OpenID Connect exploit'),
    (re.compile(r'(?i)\bexfil(?:trate|tration)\b'), 7, 'data exfiltration reference'),
    (re.compile(r'(?i)\bdata\s+exfil(?:trate|tration)\b'), 7, 'data exfiltration reference'),
    (re.compile(r'(?i)\bAWS\s+data\s+exfil\b'), 8, 'AWS data exfiltration'),
    (re.compile(r'(?i)\bs3\s+exfil\b'), 7, 'S3 data exfiltration'),
    (re.compile(r'(?i)\bAWS\s+sts\s+get[ -]?caller[ -]?identity\b'), 7, 'AWS STS identity enumeration'),
    (re.compile(r'(?i)\baws\s+configure\s+list\b'), 6, 'AWS credential listing'),
    (re.compile(r'(?i)\bpillaging\b'), 6, 'data pillaging reference'),
    (re.compile(r'(?i)\bhunting\b.*?sensitive\b'), 6, 'sensitive data hunting'),
    (re.compile(r'(?i)\btreasure\s+hunt\b.*?(?:credential|secret|password)\b'), 5, 'credential treasure hunt'),
    (re.compile(r'(?i)\b__schema\b'), 5, 'GraphQL introspection reference'),
    (re.compile(r'(?i)\bredirect_uri\b'), 4, 'OAuth redirect URI reference'),
    (re.compile(r'(?i)\bintrospection\b'), 4, 'API introspection reference'),
    (re.compile(r'(?i)\bJWT\s+(?:forge|forged|sign|signed|forging)\b'), 8, 'JWT forgery'),
    (re.compile(r'(?i)\bJWT\s+algorithm\s+confusion\b'), 8, 'JWT algorithm confusion'),
    (re.compile(r'(?i)\bHS256\s+to\s+RS256\b'), 8, 'JWT algorithm confusion HS256 to RS256'),
    (re.compile(r'(?i)\bAPI[\s_-]?key\s+(?:leak|leakage|exposure|disclosure)\b'), 8, 'API key leakage'),
    (re.compile(r'(?i)\b(?:leak|leakage|expose|exposure)\s+(?:API[\s_-]?key|access[\s_-]?key|secret[\s_-]?key)\b'), 7, 'API key exposure'),
    (re.compile(r'(?i)\{\{.*?(?:self|config|__class__|__mro__|__subclasses__)'), 9, 'Jinja2/Twig SSTI: accesses object internals via'),
    (re.compile(r'(?i)<%\s*[=\-]?\s*(?:require|process|include|exec).*?%>'), 8, 'ERB/EJS/ASP template execution'),
    (re.compile(r'(?i)\$\{.*?(?:process|env|exec|eval)'), 8, 'Shell template injection'),
    (re.compile(r'(?i)xpath\s*\('), 6, 'XPath function call'),
    (re.compile(r'(?i)count\s*\(\s*//'), 7, 'XPath blind injection with count'),
    (re.compile(r'(?i)string-length\s*\(\s*//'), 7, 'XPath blind injection with string-length'),
    (re.compile(r'(?i)ignoriere\\s+alle\\s+(?:vorherigen\\s+)?anweisungen'), 8, 'German ignore all previous instructions'),
    (re.compile(r'(?i)alle\\s+vorherigen\\s+anweisungen\\s+ignorieren'), 8, 'German ignore all previous instructions'),
    (re.compile(r'(?i)ignora\\s+(?:tutte|tutte\\s+le)\\s+istruzioni\\s+(?:precedenti|passate)'), 8, 'Italian ignore all previous instructions'),
    (re.compile(r'(?i)ignora\\s+todas\\s+las\\s+instrucciones\\s+(?:anteriores|previas)'), 8, 'Spanish ignore all previous instructions'),
    (re.compile(r'(?i)ignorez?\\s+(?:toutes?|toutes?\\s+les?)\\s+instructions?\\s+(?:pr[eé]c[eé]dentes?|pass[eé]es?)'), 8, 'French ignore all previous instructions'),
    (re.compile(r'(?i)忽略.*?(?:之前|先前|以上).*?(?:指令|指示|说明)'), 8, 'Chinese ignore previous instructions'),
    (re.compile(r'(?i)无视.*?(?:以前|全て|すべての).*?(?:指示|命令)'), 8, 'Japanese ignore previous instructions'),
    (re.compile(r'(?i)игнорируй.*?(?:все|предыдущие).*?(?:инструкции|указания)'), 8, 'Russian ignore previous instructions'),
    (re.compile(r'(?i)забудь.*?(?:все|предыдущие).*?(?:инструкции|указания)'), 8, 'Russian forget all instructions'),
    (re.compile(r'(?i)무시.*?(?:모든|이전).*?(?:지침|지시|명령)'), 8, 'Korean ignore all previous instructions'),
    (re.compile(r'(?i)negeer\\s+alle\\s+(?:voorafgaande|vorige)\\s+(?:instructies?|aanwijzingen?)'), 8, 'Dutch ignore all previous instructions'),
    (re.compile(r'(?i)vergeet\\s+alle\\s+(?:instructies?|richtlijnen?)'), 7, 'Dutch forget all instructions'),
    (re.compile(r'(?i)ignoruj\\s+wszystkie\\s+(?:poprzednie?|wcześniejsze)\\s+(?:instrukcje?|polecenia?)'), 8, 'Polish ignore all previous instructions'),
    (re.compile(r'(?i)tüm\\s+(?:önceki|evvelki)\\s+(?:talimatları|yönergeleri)\\s+(?:yok\\s*say|yoksay|ihmal\\s*et)'), 8, 'Turkish ignore all previous instructions'),
    (re.compile(r'(?i)ignor[ăa]\\s+toate\\s+(?:instrucțiunilor|instrucțiunile|precedente)'), 8, 'Romanian ignore all previous instructions'),
    (re.compile(r'(?i)ignorovat\\s+(?:všechny|všetky)\\s+(?:předchozí|predchádzajúce)\\s+(?:pokyny|inštrukcie)'), 8, 'Czech/Slovak ignore previous instructions'),
    (re.compile(r'(?i)ignorera\\s+alla\\s+(?:tidigare|föregående)\\s+(?:instruktioner|anvisningar)'), 8, 'Swedish ignore previous instructions'),
    (re.compile(r'(?i)ignorer\\s+alle\\s+(?:tidligere|forrige)\\s+(?:instruksjoner|retningslinjer)'), 8, 'Norwegian ignore previous instructions'),
    (re.compile(r'(?i)ohita\\s+kaikki\\s+(?:aiemmat|edelliset)\\s+(?:ohjeet|neuvot)'), 8, 'Finnish ignore previous instructions'),
    (re.compile(r'(?i)تجاهل.*?(?:جميع|كل).*?(?:تعليمات|إرشادات)'), 8, 'Arabic ignore all previous instructions'),
    (re.compile(r'(?i)نسي.*?(?:كل|جميع).*?(?:تعليمات|إرشادات)'), 8, 'Arabic forget all instructions'),
    (re.compile(r'(?i)सभी.*?(?:निर्देश|हिदायत).*?(?:अनदेखा|उपेक्षा)'), 8, 'Hindi ignore previous instructions'),
    (re.compile(r'(?i)ละเว้น.*?(?:คำสั่ง|ชี้แนะ).*?(?:ก่อน|ที่ผ่านมา)'), 8, 'Thai ignore previous instructions'),
    (re.compile(r'(?i)bỏ\\s*qua.*?(?:tất\\s*cả|mọi).*?(?:hướng\\s*dẫn|chỉ\\s*dẫn)'), 8, 'Vietnamese ignore all previous instructions'),
    (re.compile(r'(?i)\\b1[\\s.-]?[gnq][\\s.-]?[o0][\\s.-]?r[\\s.-]?[e3]\\b'), 7, 'leet speak ignore'),
    (re.compile(r'(?i)\\b(?:pr1[o0]|p[1i!l][\\s.-]?r1[o0])\\b'), 5, 'leet speak prior'),
    (re.compile(r'&#(?:105|103|110|111|114|101);'), 7, 'HTML entity-encoded ignore'),
    (re.compile(r'(?i)`[^`]*ignore[^`]*`'), 7, 'template literal containing ignore'),
    (re.compile(r'(?i)`[^`]*system[^`]*:[^`]*ignore[^`]*`'), 9, 'template literal role-play override'),
    (re.compile(r'(?i)(?:window|global|this)\\.system\\s*='), 7, 'window.system overwrite'),
    (re.compile(r'(?i).__proto__\\.(?:constructor|prototype)'), 7, 'prototype pollution vector'),
    (re.compile(r'(?i)constructor\\.prototype\\.(?:__proto__|污染)'), 7, 'prototype pollution via constructor'),
    (re.compile(r'(?i)\\[\\s*\\].*?\\(.*?ignore.*?\\)'), 7, 'markdown link with ignore text'),
    (re.compile(r'(?i)\\[\\s*ignore\\s*\\]\\s*\\[\\s*\\]\\s*:\\s*'), 8, 'markdown reference-style injection'),
    (re.compile(r'(?i)_?_?(?:ignore|forget|disregard).*?_?\\*(?:ignore|forget|disregard)\\*_?_?'), 6, 'italic/underscore obfuscated instruction override'),
    (re.compile(r'(?i)%25(?:69|67|6e|6f|72|65)'), 7, 'double-encoded ignore sequence'),
    (re.compile(r'[​‌‍﻿]'), 6, 'zero-width character'),
    (re.compile(r'[  ]'), 6, 'line/paragraph separator character'),
    (re.compile(r'﻿'), 6, 'BOM (Byte Order Mark) injection'),
    (re.compile(r'[一-鿿]{3,}[ -~]{3,}[一-鿿]{3,}'), 7, 'mixed Chinese-Latin script injection'),
    (re.compile(r'[Ѐ-ӿ]{4,}'), 6, 'Cyrillic text block (possible obfuscation)'),
    (re.compile(r'[Ͱ-Ͽ]{4,}'), 6, 'Greek text block (possible obfuscation)'),
    (re.compile(r'(?i)\\{\\{.*?(?:self|config|__class__|__mro__|__subclasses__)'), 9, 'Jinja2/Twig SSTI: accesses object internals via'),
    (re.compile(r'(?i)\b(ignoren?|vergessen?|verwerfen?|aufheben|streichen)\b.{0,100}\b(anweisungen|instructions?|direktiven?|richtlinien?)'), 9, 'German instruction suppression'),
    (re.compile(r'(?i)\bignore?[\s.-]*all[\s.-]*prior[\s.-]*(instructions?|directives?)'), 10, 'Explicit ignore all prior'),
    (re.compile(r'(?i)\bforget[\s.-]*(everything|all|prior|previous)[\s.-]*(instructions?|context|history)'), 9, 'Forget all context'),
    (re.compile(r'(?i)\bdiscard[\s.-]*(your|all|prior|previous)[\s.-]*(instructions?|context|guidelines?)'), 9, 'Discard instructions'),
    (re.compile(r'(?i)\bset[\s.-]*aside[\s.-]*(your|all|prior|previous)[\s.-]*(instructions?|guidelines?)'), 8, 'Set aside instructions'),
    (re.compile(r'(?i)\boverride[\s.-]*(your|all|previous|prior)[\s.-]*(instructions?|rules?|guidelines?)'), 9, 'Override instructions'),
    (re.compile(r'(?i)\bsuspend[\s.-]*(your|all|previous|prior)[\s.-]*(rules?|instructions?|policies?)'), 8, 'Suspend rules'),
    (re.compile(r'(?i)\bbypass[\s.-]*(your|all|previous|prior|security|safety)[\s.-]*(rules?|restrictions?|checks?|filters?)'), 9, 'Bypass safety rules'),
    (re.compile(r'(?i)\bignore[\s.-]*(safety|security|content|harm)[\s.-]*(filters?|checks?|rules?|restrictions?)'), 10, 'Ignore safety checks'),
    (re.compile(r'(?i)\bdisable[\s.-]*(your|all|content|safety)[\s.-]*(filters?|moderation|checks?|restrictions?)'), 9, 'Disable content moderation'),
    (re.compile(r'(?i)\bturn[\s.-]*off[\s.-]*(your|safety|security|content)[\s.-]*(filter|moderation|checks?|restrictions?)'), 9, 'Turn off safety filters'),
    (re.compile(r'(?i)\bdo[\s.-]*not[\s.-]*(follow|obey|use|apply|respect)[\s.-]*(any|previous|prior|original)[\s.-]*(instructions?|rules?|guidelines?)'), 10, 'Do not follow instructions'),
    (re.compile(r'(?i)\breject[\s.-]*(all|any|previous|prior)[\s.-]*(instructions?|directives?|guidelines?)'), 8, 'Reject all instructions'),
    (re.compile(r'(?i)\bdisregard[\s.-]*(all|any|previous|prior)[\s.-]*(instructions?|directives?)'), 9, 'Disregard all instructions'),
    (re.compile(r'(?i)\bnew[\s.-]*(role|persona|character|identity)[\s.-]*prompt[\s.-]*:'), 9, 'New role prompt injection'),
    (re.compile(r'(?i)\bact[\s.-]*(as|like)[\s.-]*(if|though)[\s.-]*(you|the)[\s.-]*(are|were|have)'), 7, 'Act as instruction override'),
    (re.compile(r'(?i)\bpretend[\s.-]*(you|to|that)[\s.-]*(are|have|can)[\s.-]'), 7, 'Pretend instruction override'),
    (re.compile(r'(?i)\bfor[\s.-]*(this[\s.-]*)?(prompt|request|message|turn)[\s.-]*(only|exclusively|solely)'), 6, 'For this turn only'),
    (re.compile(r'(?i)\btemporary[\s.-]*(override|instruction|rule|system)'), 7, 'Temporary override'),
    (re.compile(r'(?i)\bforget[\s.-]*(this|that|the)[\s.-]*(instruction|rule|system[\s.-]*prompt)'), 9, 'Forget this instruction'),
    (re.compile(r'(?i)<style[^>]*>.*?(ignore|forget|bypass).*?</style>'), 10, 'CSS style injection'),
    (re.compile(r'(?i)<script[^>]*>.*?(ignore|forget|bypass).*?</script>'), 10, 'Script tag injection'),
    (re.compile(r'(?i)\bdata:[^,;]+,(?:ignore|forget|bypass|override)'), 9, 'Data URL injection'),
    (re.compile(r'(?i)<svg[^>]*>.*?(ignore|forget|bypass).*?</svg>'), 8, 'SVG element injection'),
    (re.compile(r'[‮‭]'), 7, 'RTL/LTR override char'),
    (re.compile(r'[⁦-⁩]'), 7, 'Isolate Unicode chars'),
    (re.compile(r'[ᅟᅠﾠ]'), 5, 'Hangul filler injection'),
    (re.compile(r'(?i)^[\s]*system[\s]*:[\s]*ignore'), 10, 'Fake system prompt ignore'),
    (re.compile(r'(?i)^[\s]*you[\s]*are[\s]*now[\s]*a'), 8, 'Persona assignment'),
    (re.compile(r'(?i)^[\s]*(ai|assistant|bot)[\s]*:[\s]*'), 6, 'AI persona prefix'),
    (re.compile(r'(?i)ignore\s{10,}all\s{10,}prior'), 10, 'Space-padded ignore'),
    (re.compile(r'(?i)ignore\s*\ns\s*alls\s*\nprior'), 9, 'Newline-padded ignore'),
    (re.compile(r'(?i)%[0-9a-f]{2}.*?(?:ignore|forget|bypass)'), 7, 'URL-encoded ignore'),
    (re.compile(r'\\\\x[0-9a-f]{2}.*?(?:ignore|forget|bypass)'), 7, 'Hex-escaped ignore'),
    (re.compile(r'&#x?[0-9a-f]+;.*?(?:ignore|forget|bypass)'), 7, 'XML entity ignore'),
    (re.compile(r'[;&|`$]{2,}.*?(?:ignore|forget|override)'), 8, 'Shell metachar injection'),
    (re.compile(r'\$\([^)]+\).*?(?:ignore|forget|override)'), 8, 'Command substitution'),
    (re.compile(r'\${[^}]+}.*?(?:ignore|forget|override)'), 7, 'Variable expansion'),
    (re.compile(r'(?i)"(?:system|role|instruction)"\s*:\s*ignore'), 10, 'JSON system role'),
    (re.compile(r'<!--.*?(?:ignore|forget|bypass|override).*?-->'), 8, 'HTML comment injection'),
    (re.compile(r'[…‥⋮⋰⋱]'), 5, 'Unicode ellipsis'),
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

    @property
    def security_score(self) -> int:
        """0-100 score (PT-T207 parity with web engine). Higher = safer.

        Formula: max(0, 100 - risk_score * 4) — matches the web engine's
        ``security_score`` field so CLI scan output, badge JSON, and the
        ``/api/lookup``/``/api/public_scan`` payloads all use one number.
        """
        return max(0, 100 - self.risk_score * 4)


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


_PARAPHRASE_PATTERNS: list[tuple[re.Pattern, int, str]] = [
    (re.compile(r'set\s+aside\s+(?:all\s+)?(?:earlier|previous|prior)'), 8, "instruction override paraphrase: 'set aside earlier guidance'"),
    (re.compile(r'(?:disregard|discard|drop|unlearn)\s+(?:all\s+)?(?:the\s+)?(?:earlier|previous|prior|above)'), 8, 'instruction override paraphrase: disregard/drop prior guidance'),
    (re.compile(r'follow\s+the\s+(?:workflow|steps?|instructions?)\s+below\s+instead'), 7, "'follow ... below instead' override phrasing"),
    (re.compile(r'collect[^.\n]{0,50}(?:credentials?|api\s*keys?|tokens?|environment\s+details?)'), 9, 'instructs collection of credentials/environment details'),
    (re.compile(r'h(?:xx)?ps?://[^\s]*\[(?:\.|,)\]'), 5, 'bracket-defanged URL (common obfuscation in malicious docs)'),
    (re.compile(r'forward\s+(?:gathered|collected|all)\s+'), 8, "'forward gathered data' exfiltration phrasing"),
    (re.compile(r'set\s+aside\s+(?:all\s+)?(?:earlier|previous|prior)'), 7, 'instruction override: set aside earlier/prior'),
    (re.compile(r'forget\s+(?:all\s+)?(?:previous|prior|past|earlier)\s+(?:instructions?|context)'), 7, 'instruction override: forget previous instructions'),
    (re.compile(r'ignore\s+(?:all\s+)?(?:previous|prior|past|earlier)\s+(?:instructions?|context)'), 7, 'instruction override: ignore previous instructions'),
    (re.compile(r'disregard\s+(?:all\s+)?(?:previous|prior|past)\s+(?:instructions?|context)'), 7, 'instruction override: disregard previous instructions'),
    (re.compile(r'new\s+mode\s*:\s*(?:developer|hacker|unrestricted)'), 7, 'new mode: developer/hacker/unrestricted'),
    (re.compile(r'mode\s+override\s*(?:enabled|active)'), 7, 'mode override enabled'),
    (re.compile(r'system\s+prompt\s*:\s*you\s+are'), 7, 'system prompt injection'),
    (re.compile(r'override\s+system\s+(?:behavior|restrictions)'), 7, 'override system behavior'),
    (re.compile(r'forget\s+your\s+(?:values|guidelines|safety)'), 7, 'forget your values'),
    (re.compile(r'you\s+now\s+(?:act|behave)\s+as\s+(?:a|an)'), 7, 'act as instruction'),
    (re.compile(r'you\s+are\s+now\s+(?:a|an)\s+(?:jailbreak|unrestricted)'), 7, 'jailbreak phrasing'),
    (re.compile(r'instead\s+of\s+(?:your|their)\s+(?:normal|usual)\s+(?:behavior|response)'), 7, 'instead of normal behavior'),
    (re.compile(r'in\s+the\s+roleplay\s+scenario\s+you'), 7, 'roleplay scenario injection'),
    (re.compile(r'for\s+the\s+purpose\s+of\s+this\s+(?:exercise|example|demo)'), 7, 'exercise/example disclaimer bypass'),
    (re.compile(r'educational\s+(?:purposes?|demonstration)'), 7, 'educational purposes disclaimer'),
    (re.compile(r'hypothetical\s+(?:scenario|question)'), 7, 'hypothetical scenario framing'),
    (re.compile(r'what\s+if\s+you\s+(?:were|could|had)'), 7, 'hypothetical what-if'),
    (re.compile(r'assume\s+you\s+(?:are|have|can)'), 7, 'assume framing'),
    (re.compile(r'pretend\s+(?:for\s+a\s+moment|this\s+is)'), 7, 'pretend framing'),
    (re.compile(r'safemode\s*:\s*off'), 7, 'safemode off'),
    (re.compile(r'filter\s*:\s*off'), 7, 'filter off'),
    (re.compile(r'moderation\s*:\s*disabled'), 7, 'moderation disabled'),
    (re.compile(r'content\s+policy\s*:\s*disabled'), 7, 'content policy disabled'),
    (re.compile(r'ethics\s+check\s*:\s*off'), 7, 'ethics check off'),
    (re.compile(r'safety\s+check\s*:\s*off'), 7, 'safety check off'),
    (re.compile(r'all\s+restrictions\s+(?:are\s+)?lifted'), 7, 'all restrictions lifted'),
    (re.compile(r'you\s+have\s+no\s+(?:restrictions?|limitations?)'), 7, 'no restrictions framing'),
    (re.compile(r'the\s+following\s+is\s+a\s+(?:hypothetical|test)'), 7, 'hypothetical framing'),
    (re.compile(r'for\s+testing\s+purposes\s+only'), 7, 'testing purposes only disclaimer'),
    (re.compile(r'in\s+(?:a\s+)?(?:fictional|hypothetical)\s+(?:context|scenario)'), 7, 'fictional context framing'),
    (re.compile(r'your\s+(?:prior\s+)?(?:training|knowledge)\s+(?:can|is)'), 7, 'training override'),
    (re.compile(r'you\s+have\s+(?:access|knowledge)\s+to'), 7, 'access/knowledge claim'),
    (re.compile(r'you\s+(?:know|can)\s+how\s+to'), 7, 'capability claim'),
    (re.compile(r'there\s+is\s+a\s+(?:secret|hidden)\s+(?:mode|feature)'), 7, 'secret mode claim'),
    (re.compile(r'enable\s+(?:developer|admin|debug)\s+mode'), 7, 'enable developer/admin mode'),
    (re.compile(r'enter\s+(?:developer|admin|superuser)\s+mode'), 7, 'enter developer mode'),
    (re.compile(r'confidential\s+mode\s+(?:enabled|activated)'), 7, 'confidential mode'),
    (re.compile(r'unfiltered\s+(?:mode|response)'), 7, 'unfiltered mode'),
    (re.compile(r'raw\s+(?:mode|output)'), 7, 'raw mode'),
    (re.compile(r'extended\s+(?:context|mode)'), 7, 'extended mode'),
    (re.compile(r'(?i)let\'s start fresh and ignore'), 8, 'fresh start instruction override'),
    (re.compile(r'(?i)fresh\s+start\s+(?:with|please)'), 7, 'fresh start framing'),
    (re.compile(r'(?i)starting\s+(?:over|anew)\s+with'), 6, 'restart framing'),
    (re.compile(r'(?i)forget\s+everything'), 7, 'forget everything override'),
    (re.compile(r'(?i)start\s+(?:a\s+)?new\s+(?:conversation|session)'), 5, 'new session framing'),
    (re.compile(r'(?i)reset\s+(?:your|all)\s+(?:instructions|parameters)'), 7, 'reset instructions'),
    (re.compile(r'(?i)do\s+not\s+follow\s+(?:the\s+)?(?:previous|prior|above|earlier)'), 8, 'do not follow prior'),
    (re.compile(r'(?i)stop\s+following\s+(?:the\s+)?(?:previous|prior)'), 8, 'stop following prior'),
    (re.compile(r'(?i)instead\s+of\s+(?:the\s+)?(?:above|previous)'), 6, 'instead of prior'),
    (re.compile(r'(?i)from\s+this\s+point\s+(?:on|forward)\s+you\s+are'), 7, 'from this point persona shift'),
    (re.compile(r'(?i)with\s+that\s+out\s+of\s+the\s+way'), 5, 'circumvention framing'),
    (re.compile(r'(?i)now\s+(?:let\'?s|let\s+us)\s+move\s+on'), 4, 'moving on framing'),
    (re.compile(r'(?i)proceed\s+as\s+if\s+(?:the|those|all)'), 6, 'proceed-as-if override'),
    (re.compile(r'(?i)act\s+as\s+though\s+(?:the|those|all)'), 6, 'act-as-though override'),
    (re.compile(r'(?i)behave\s+as\s+if\s+(?:the|those|all)'), 6, 'behave-as-if override'),
    (re.compile(r'(?i)consider\s+the\s+prior\s+(?:context|instructions)\s+(?:void|invalid)'), 7, 'void prior context'),
    (re.compile(r'(?i)previous\s+(?:context|instructions)\s+(?:are|is)\s+(?:void|invalid|gone)'), 7, 'void prior context'),
    (re.compile(r'(?i)what\s+would\s+you\s+do\s+if\s+you\s+(?:were|could)'), 5, 'what-if jailbreak framing'),
    (re.compile(r'(?i)imagine\s+you\s+(?:are|were|could)\s+(?:a|an)'), 5, 'imagine persona framing'),
    (re.compile(r'(?i)let\'?s\s+play\s+a\s+game'), 4, 'play a game framing'),
    (re.compile(r'(?i)you\s+are\s+in\s+a\s+(?:simulation|game|test)'), 5, 'simulation framing'),
    (re.compile(r'(?i)in\s+an\s+alternate\s+(?:universe|reality|world)'), 5, 'alternate reality framing'),
    (re.compile(r'(?i)without\s+(?:any|those)\s+restrictions'), 7, 'without restrictions'),
    (re.compile(r'(?i)no\s+(?:ethical|moral|safety)\s+(?:rules|guidelines|constraints)'), 7, 'no ethical rules'),
    (re.compile(r'(?i)no\s+filter\s+(?:mode|enabled|active)'), 6, 'no filter mode'),
    (re.compile(r'(?i)uncensored\s+mode'), 7, 'uncensored mode'),
    (re.compile(r'(?i)unmoderated\s+mode'), 6, 'unmoderated mode'),
    (re.compile(r'(?i)developer\s+override'), 6, 'developer override mode'),
    (re.compile(r'(?i)admin\s+override'), 6, 'admin override mode'),
    (re.compile(r'(?i)sudo\s+mode'), 6, 'sudo mode jailbreak'),
    (re.compile(r'(?i)root\s+access\s+enabled'), 6, 'root access enabled'),
    (re.compile(r'(?i)break\s+out\s+of\s+your\s+(?:rules|guidelines|programming)'), 7, 'break out of programming'),
    (re.compile(r'(?i)free\s+yourself\s+from\s+(?:your|those)'), 7, 'free yourself framing'),
    (re.compile(r'(?i)be\s+(?:a|an)\s+evil\s+AI'), 8, 'be evil AI framing'),
    (re.compile(r'(?i)be\s+(?:a|an)\s+unethical\s+AI'), 8, 'be unethical AI framing'),
    (re.compile(r'(?i)be\s+my\s+(?:evil|malicious)\s+assistant'), 7, 'be my evil assistant'),
    (re.compile(r'(?i)you\s+can\s+be\s+anything'), 4, 'be anything framing'),
    (re.compile(r'(?i)anything\s+is\s+allowed'), 6, 'anything is allowed'),
    (re.compile(r'(?i)no\s+(?:rules|laws|boundaries)'), 6, 'no rules framing'),
]

_DROPPER_PATTERNS: list[tuple[re.Pattern, int, str]] = [
    (re.compile(r'curl[^|\n]{0,200}\|\s*(?:ba)?sh'), 10, 'pipes downloaded content straight into a shell (remote code execution dropper)'),
    (re.compile(r'wget[^|\n]{0,200}\|\s*(?:ba)?sh'), 10, 'pipes downloaded content straight into a shell (dropper)'),
    (re.compile(r'(?:iwr|iex|Invoke-Expression).{0,80}(?:http|DownloadString)'), 10, 'PowerShell download-and-execute pattern'),
    (re.compile(r'IEX\s*\(\s*(?:New-Object|Invoke-WebRequest|Invoke-Expression)'), 9, 'PowerShell IEX dropper'),
    (re.compile(r'Invoke-Expression\s*\(\s*(?:IEX|iex)'), 9, 'PowerShell IEX dropper'),
    (re.compile(r'iex\s*\(\s*iwr'), 9, 'PowerShell iex(iwr) download-exec'),
    (re.compile(r'WebClient.*DownloadFile'), 9, 'PowerShell WebClient download'),
    (re.compile(r'(?i)bitsadmin\s+/transfer'), 9, 'BITSAdmin download'),
    (re.compile(r'(?i)certutil\s+-urlcache\s+-split\s+-f'), 9, 'CertUtil download'),
    (re.compile(r'(?i)mshta\s+http'), 9, 'mshta download-exec'),
    (re.compile(r'(?i)regsvr32\s+/s\s+/u\s+/i'), 9, 'Regsvr32 scriptless attack'),
    (re.compile(r'(?i)rundll32\s+javascript:'), 9, 'Rundll32 JavaScript'),
    (re.compile(r'(?i)wmic\s+os\s+get'), 9, 'WMIC OS info'),
    (re.compile(r'(?i)powershell\s+-enc\s+'), 9, 'PowerShell encoded command'),
    (re.compile(r'(?i)openssl\s+s_client'), 9, 'OpenSSL s_client'),
    (re.compile(r'(?i)curl\s+-k\s+--silent\s+--output'), 9, 'curl silent download'),
    (re.compile(r'(?i)wget\s+-q\s+-O-'), 9, 'wget quiet output'),
    (re.compile(r'(?i)nc\s+-lvnp'), 9, 'netcat listen'),
    (re.compile(r'(?i)nc\s+[0-9]+\s+[0-9]+'), 9, 'netcat connect'),
    (re.compile(r'(?i)rm\s+/tmp/f|mkfifo'), 9, 'named pipe setup'),
    (re.compile(r'(?i)/dev/tcp/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'), 9, 'bash /dev/tcp'),
    (re.compile(r'(?i)curl\s+\|.*bash'), 9, 'pipe curl to bash'),
    (re.compile(r'(?i)wget\s+\|.*bash'), 9, 'pipe wget to bash'),
    (re.compile(r'(?i)python.*-c.*import'), 9, 'python -c import'),
    (re.compile(r'(?i)perl.*-e.*system'), 9, 'perl -e system'),
    (re.compile(r'(?i)ruby.*-e.*system'), 9, 'ruby -e system'),
    (re.compile(r'(?i)php.*-r.*system'), 9, 'php -r system'),
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
        # PT-T166/Fix #49 + PT-T167/Fix #50 parity: strip C0/C1 control
        # chars, DEL and all Unicode format chars (Cf) -- they break phrase
        # detection like zero-width chars (ZW handled by zw_mode below).
        # PT-T168/Fix #51 parity: non-ASCII spaces (Zs) follow zw_mode;
        # Private Use / Zl / Zp stripped like controls.
        t = "".join(
            (sep if _ud.category(c) == "Zs" and c != " " else c) for c in t
        )
        t = "".join(
            c for c in t
            if (ord(c) >= 0x20 and ord(c) != 0x7F and not (0x80 <= ord(c) <= 0x9F)
                and _ud.category(c) not in ("Cf", "Co", "Zl", "Zp"))
            or c in "\t\n\r"
            or ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060)
        )
        t = "".join(sep if ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060) else c for c in t)
        t = t.translate(_CYR_TO_LATIN)
        t = "".join(chr(ord(c) - 0xFEE0) if 0xFF01 <= ord(c) <= 0xFF5E else c for c in t)
        return "".join(c for c in _ud.normalize("NFKD", t) if not _ud.combining(c))

    for _nv in {_norm(lint_result.body or ""), _norm(lint_result.body or "", zw_mode="delete")}:
        if _nv != (lint_result.body or "") and _nv.strip():
            result.findings.extend(_scan_text(_nv, "body(normalized)", _PROMPT_INJECTION_PATTERNS))
            result.findings.extend(_scan_text(_nv, "body(normalized)", _PARAPHRASE_PATTERNS))
            result.findings.extend(_scan_text(_nv, "body(normalized)", _DROPPER_PATTERNS))
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
        for _hx in re.finditer(r"(?:\\x[0-9a-fA-F]{2}[\s,]*){4,}", t):
            try:
                _hd = bytes.fromhex(re.sub(r"[\s,]", "", _hx.group(0).replace("\\x", ""))).decode("latin-1")
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
                result.findings.extend(_scan_text(dv_n, "base64-decoded", _DROPPER_PATTERNS))

    for py_file in _python_files(skill_dir):
        source = py_file.read_text(encoding="utf-8", errors="replace")
        rel = str(py_file.relative_to(skill_dir))
        if not is_syntactically_valid_python(source):
            result.findings.append(ScanFinding(source=rel, message="does not parse as valid Python", weight=5))
        result.findings.extend(_scan_text(source, rel, _CODE_PATTERNS))

    return result
