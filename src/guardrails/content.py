"""Content and path category detection for publication policy."""

from __future__ import annotations

from pathlib import PurePosixPath
import re

MAX_BYTES = 256 * 1024

DENIED_DIRS = {
    "private",
    "data",
    "datasets",
    "exports",
    "export",
    "backups",
    "backup",
    "dumps",
    "dump",
    "secrets",
    "credentials",
    "local",
    ".scratch",
    ".agent",
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    ".opencode",
    ".pi",
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
}
DENIED_SUFFIXES = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".sql",
    ".dump",
    ".bak",
    ".backup",
    ".csv",
    ".tsv",
    ".jsonl",
    ".ndjson",
    ".parquet",
    ".avro",
    ".orc",
    ".arrow",
    ".feather",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".ods",
    ".numbers",
    ".zip",
    ".gz",
    ".tgz",
    ".7z",
    ".rar",
    ".tar",
    ".bz2",
    ".xz",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".crt",
    ".cer",
    ".jks",
    ".keystore",
    ".pdf",
    ".doc",
    ".docx",
    ".pages",
    ".rdb",
    ".mdb",
    ".accdb",
}
JSON_MANIFESTS = {
    ".public-repo-policy.json",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "jsconfig.json",
    "deno.json",
    "biome.json",
}
SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
    ),
    (
        "provider-secret",
        re.compile(r"\bsk-(?:proj-|ant-[A-Za-z0-9-]*-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    ("stripe-secret", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{15,}\b")),
    ("google-key", re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b")),
    ("google-client-secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b")),
    ("supabase-secret", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    ("service-account", re.compile(r'''["']type["']\s*:\s*["']service_account["']''')),
    ("credential-url", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@", re.I)),
]
KEY_NAME = (
    r"(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|password|passwd|secret|token|authorization|"
    r"connection[_-]?string)(?:[_-][A-Za-z0-9]+)*"
)
QUOTED_CREDENTIAL = re.compile(
    r'''(?<![\w-])["']?(?:''' + KEY_NAME + r''')["']?\s*[:=]\s*(["'])([^\r\n]*?)\1''',
    re.I,
)
BARE_CREDENTIAL = re.compile(
    r"^[ \t]*(?:export[ \t]+)?(?:" + KEY_NAME + r")[ \t]*[:=][ \t]*([^\r\n]*)$",
    re.I | re.M,
)


def placeholder(value: str) -> bool:
    return (
        not value
        or bool(re.fullmatch(r"(?:YOUR|EXAMPLE)_[A-Z0-9_]+", value))
        or bool(re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", value))
        or bool(
            re.fullmatch(
                r"\$\{\{\s*(?:secrets|github|env|vars)\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}",
                value,
            )
        )
    )


def content_categories(raw: bytes, path: str = "") -> set[str]:
    if len(raw) > MAX_BYTES:
        return {"oversized-file"}
    if b"\x00" in raw:
        return {"binary-file"}
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"non-utf8-file"}
    found = {name for name, pattern in SECRET_PATTERNS if pattern.search(content)}
    for match in QUOTED_CREDENTIAL.finditer(content):
        if not placeholder(match.group(2)):
            found.add("hardcoded-credential")
    for match in BARE_CREDENTIAL.finditer(content):
        value = match.group(1).strip().split(" #", 1)[0]
        if value.startswith(("'", '"')):
            continue  # The quoted detector handles literal values.
        name = PurePosixPath(path).name.casefold()
        strict_config = name.startswith(".env") or name.endswith(
            (".yaml", ".yml", ".toml", ".ini", ".conf")
        )
        expression = any(char in value for char in "()[]{};,")
        if not placeholder(value) and (strict_config or not expression):
            found.add("hardcoded-credential")
    return found


def path_categories(path: str, mode: str, allowed: set[str]) -> set[str]:
    found: set[str] = set()
    if content_categories(path.encode("utf-8", errors="surrogateescape")):
        found.add("credential-or-invalid-content-in-path")
    if path not in allowed:
        found.add("path-not-approved")
    pure = PurePosixPath(path)
    parts = tuple(part.casefold() for part in pure.parts)
    name = parts[-1] if parts else ""
    if any(part in DENIED_DIRS for part in parts[:-1]):
        found.add("private-or-local-directory")
    if name.startswith(".env") and name != ".env.example":
        found.add("environment-file")
    if (
        any(suffix in DENIED_SUFFIXES for suffix in PurePosixPath(name).suffixes)
        or re.search(r"\.(?:db|sqlite3?)-(?:wal|shm|journal)$", name)
        or name
        in {
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            ".netrc",
            ".npmrc",
            ".pypirc",
            ".gitleaksignore",
        }
    ):
        found.add("sensitive-data-or-key-file")
    if (
        name.endswith(".json")
        and name not in JSON_MANIFESTS
        and not re.fullmatch(r"tsconfig\.[a-z0-9_-]+\.json", name)
    ):
        found.add("non-manifest-json-data")
    if mode not in {"100644", "100755"}:
        found.add("symlink-submodule-or-special-file")
    if (
        not path
        or pure.is_absolute()
        or ".." in pure.parts
        or "\\" in path
        or any(ord(char) < 32 for char in path)
    ):
        found.add("unsafe-path")
    return found
