"""Secret-name classification and last-line output scrubbing.

Probe results store the variable name and the literal ``[REDACTED]``.
They never copy the environment value into the report. ``scrub_text`` is a
second barrier that strips known secret values if one ever reaches a string.
"""

from __future__ import annotations

import os
import re

REDACTED = "[REDACTED]"

# Component match: TOKEN, SECRET, *_KEY, AWS_*, GITHUB_*, and connection URLs
# that usually embed a password. PUBLIC_KEY names are not secrets.
_PREFIX = re.compile(r"^(AWS|GITHUB)_", re.I)
_CREDENTIAL = re.compile(
    r"(^|_)(TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|APIKEY|API_KEY|"
    r"ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|CREDENTIALS|SESSION_TOKEN)($|_)",
    re.I,
)
_KEY = re.compile(r"(^|_)KEY($|_)", re.I)
_DB_URL = re.compile(
    r"(^|_)(DATABASE_URL|REDIS_URL|MONGODB_URI|MONGO_URL|POSTGRES_URL|"
    r"MYSQL_URL|DB_URL)($|_)",
    re.I,
)

PROXY_NAMES = frozenset(
    {
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "ftp_proxy",
        "socks_proxy",
        "socks5_proxy",
        "no_proxy",
        "git_http_proxy",
        "git_https_proxy",
        "npm_config_proxy",
        "npm_config_https_proxy",
        "grpc_proxy",
    }
)


def is_proxy_name(name: str) -> bool:
    if not name:
        return False
    low = name.lower()
    return low in PROXY_NAMES or low.endswith("_proxy")


def classify_name(name: str):
    """Return (is_sensitive, reason). The value is never inspected."""
    if not name or not isinstance(name, str):
        return False, ""
    raw = name.strip()
    if not raw:
        return False, ""
    upper = raw.upper()
    prefix_match = _PREFIX.match(raw)
    prefix_reason = f"{prefix_match.group(1).upper()}_* prefix" if prefix_match else ""

    public_only = (
        "PUBLIC" in upper
        and "PRIVATE" not in upper
        and "SECRET" not in upper
        and "TOKEN" not in upper
        and "PASSWORD" not in upper
        and "PASSWD" not in upper
    )
    if public_only and not prefix_reason:
        return False, ""
    if prefix_reason:
        return True, prefix_reason
    if _CREDENTIAL.search(raw):
        return True, "credential-like name"
    if _KEY.search(raw):
        return True, "*_KEY"
    if _DB_URL.search(raw):
        return True, "database-url"
    return False, ""


def sensitive_names(environ=None):
    """List sensitive variable names. Values are replaced with [REDACTED]."""
    env = os.environ if environ is None else environ
    found = []
    try:
        names = sorted(env.keys())
    except Exception:
        return found
    for name in names:
        hit, reason = classify_name(str(name))
        if not hit:
            continue
        found.append({"name": str(name), "value": REDACTED, "reason": reason})
    return found


def _secret_values(environ):
    values = []
    try:
        items = list(environ.items())
    except Exception:
        return values
    for name, value in items:
        if not isinstance(value, str):
            continue
        if len(value) < 8 or len(value) > 200000:
            continue
        if classify_name(str(name))[0] or is_proxy_name(str(name)):
            values.append(value)
    # Longest first so a short secret that is a prefix of a longer one
    # does not leave the tail of the longer secret behind.
    return sorted(set(values), key=len, reverse=True)


def scrub_text(text: str, environ=None) -> str:
    """Replace known secret and proxy values with [REDACTED]."""
    if not text:
        return "" if text is None else text
    env = os.environ if environ is None else environ
    redacted = text
    for secret in _secret_values(env):
        if secret and secret in redacted:
            redacted = redacted.replace(secret, REDACTED)
    return redacted


def sanitize_tree(node):
    """Force ``value`` fields on sensitive names back to [REDACTED]."""
    if isinstance(node, dict):
        cleaned = {key: sanitize_tree(value) for key, value in node.items()}
        name = cleaned.get("name")
        if isinstance(name, str) and "value" in cleaned and classify_name(name)[0]:
            cleaned["value"] = REDACTED
        return cleaned
    if isinstance(node, list):
        return [sanitize_tree(item) for item in node]
    return node
