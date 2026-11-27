"""ANSI terminal dashboard and the safe-share block."""

from __future__ import annotations

import re
import shutil

from ghostleak import __version__
from ghostleak.i18n import describe, severity_label, share_line, t, tier_label
from ghostleak.parsers import format_endpoint

_ANSI = re.compile(r"\033\[[0-9;]*m")

BANNER = r"""
   ____ _               _   _               _
  / ___| |__   ___  ___| |_| |    ___  __ _| | __
 | |  _| '_ \ / _ \/ __| __| |   / _ \/ _` | |/ /
 | |_| | | | | (_) \__ \ |_| |__|  __/ (_| |   <
  \____|_| |_|\___/|___/\__|_____\___|\__,_|_|\_\
""".strip("\n")

_PROBE_ORDER = ("os", "network", "ports", "env", "firewall", "browser")

_PROBE_FINDINGS = {
    "os": set(),
    "network": {"no_vpn"},
    "ports": {"wildcard_listener", "interface_listener"},
    "env": {
        "sensitive_env",
        "ssh_world_readable",
        "ssh_permissive",
        "history_world_readable",
        "history_group_readable",
        "secret_file_exposed",
        "secret_file_group",
        "config_world_writable",
    },
    "firewall": {"firewall_off", "firewall_unknown", "running_as_root"},
    "browser": {"browser_no_privacy"},
}


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text or "")


class Theme:
    def __init__(self, enabled: bool):
        self.enabled = bool(enabled)

    def c(self, code: str, text: str) -> str:
        if not self.enabled:
            return "" if text is None else str(text)
        return f"\033[{code}m{text}\033[0m"

    def cyan(self, text):
        return self.c("96", text)

    def green(self, text):
        return self.c("92", text)

    def yellow(self, text):
        return self.c("93", text)

    def red(self, text):
        return self.c("91", text)

    def magenta(self, text):
        return self.c("95", text)

    def dim(self, text):
        return self.c("2", text)

    def bold(self, text):
        return self.c("1", text)

    def white(self, text):
        return self.c("97", text)

    def tier(self, tier: str, text: str) -> str:
        codes = {"LOW": "92", "MODERATE": "93", "HIGH": "91", "CRITICAL": "1;91"}
        return self.c(codes.get(tier, "97"), text)

    def severity(self, severity: str, text: str) -> str:
        return self.tier(severity.upper(), text)


def term_width(default: int = 78) -> int:
    try:
        width = shutil.get_terminal_size(fallback=(default, 24)).columns
    except Exception:
        width = default
    if width < 40:
        return 40
    if width > 100:
        return 100
    return width


def meter(score: int, width: int = 24, plain: bool = False) -> str:
    try:
        value = int(score)
    except (TypeError, ValueError):
        value = 0
    if value < 0:
        value = 0
    if value > 100:
        value = 100
    filled = int(value / 100 * width + 0.5)
    if filled > width:
        filled = width
    if plain:
        bar = "#" * filled + "-" * (width - filled)
    else:
        bar = "█" * filled + "░" * (width - filled)
    return "[" + bar + "]"


def _clip(text, limit: int, plain: bool) -> str:
    value = "" if text is None else str(text).replace("\n", " ")
    if len(value) <= limit:
        return value
    end = "..." if plain else "…"
    keep = max(1, limit - len(end))
    return value[:keep] + end


def _rule(title: str, width: int, theme: Theme) -> str:
    label = f" {title} "
    pad = max(4, width - len(label))
    if theme.enabled:
        return theme.cyan("─" * 2 + label + "─" * max(0, pad - 2))
    return "--" + label + "-" * max(0, pad - 2)


def _missing(lang: str) -> str:
    return t(lang, "not_available")


def _yes_no(lang: str, value) -> str:
    if value is True:
        return t(lang, "yes")
    if value is False:
        return t(lang, "no")
    return _missing(lang)


def _kv(theme: Theme, label: str, value: str) -> str:
    shown = label
    if len(shown) > 12:
        shown = shown[:12]
    return "  " + theme.dim(shown.ljust(12)) + " " + value


def _status_word(section: dict, lang: str, theme: Theme, warn: bool) -> str:
    status = (section or {}).get("status") or "restricted"
    if warn and status == "ok":
        return theme.yellow(t(lang, "warn"))
    if status == "ok":
        return theme.green(t(lang, "ok"))
    if status == "restricted":
        return theme.yellow(t(lang, "restricted"))
    return theme.dim(t(lang, "not_available"))


def _banner(theme: Theme, width: int) -> list:
    lines = []
    art = BANNER.splitlines()
    art_width = max(len(line) for line in art)
    if width >= art_width + 2:
        for line in art:
            lines.append(theme.cyan(line) if theme.enabled else line)
    word = f"GHOSTLEAK CLI  v{__version__}"
    lines.append(theme.c("1;96", word) if theme.enabled else word)
    return lines


def _readout(report: dict, lang: str, theme: Theme) -> list:
    sections = report.get("sections") or {}
    codes = {finding.code for finding in report.get("findings") or []}
    lines = [_rule(t(lang, "readout"), report.get("_width") or 78, theme)]
    for name in _PROBE_ORDER:
        section = sections.get(name) or {"status": "restricted"}
        warn = bool(codes & _PROBE_FINDINGS.get(name, set()))
        title = t(lang, f"probe.{name}")
        word = _status_word(section, lang, theme, warn)
        visible = strip_ansi(word)
        if visible.startswith("[") and visible.endswith("]"):
            lines.append(f"  {word}  {title}")
        else:
            lines.append(f"  [{word}]  {title}")
    return lines


def _os_panel(report, lang, theme, plain) -> list:
    info = (report.get("sections") or {}).get("os") or {}
    lines = [_rule(t(lang, "probe.os"), report["_width"], theme)]
    rows = [
        ("system", info.get("system")),
        ("distro", info.get("distro")),
        ("kernel", info.get("kernel")),
        ("arch", info.get("arch")),
    ]
    cpu_bits = []
    if info.get("cpu_cores"):
        cpu_bits.append(f"{info['cpu_cores']} cores")
    if info.get("cpu_model"):
        cpu_bits.append(str(info["cpu_model"]))
    rows.append(("cpu", " · ".join(cpu_bits) if cpu_bits and not plain else " | ".join(cpu_bits)))
    rows.append(("hostname", info.get("hostname")))
    rows.append(("termux", _yes_no(lang, info.get("termux"))))
    rows.append(("android", _yes_no(lang, info.get("android"))))
    rows.append(("timezone", info.get("timezone")))
    rows.append(("locale", info.get("locale")))
    rows.append(("python", info.get("python")))
    for key, value in rows:
        shown = _missing(lang) if value in (None, "") else _clip(value, 56, plain)
        lines.append(_kv(theme, t(lang, f"field.{key}"), shown))
    return lines


def _network_panel(report, lang, theme, plain) -> list:
    info = (report.get("sections") or {}).get("network") or {}
    lines = [_rule(t(lang, "probe.network"), report["_width"], theme)]
    status = info.get("status")
    if status != "ok" and not info.get("interfaces"):
        lines.append("  " + _status_word(info, lang, theme, False))
    shown = 0
    for iface in info.get("interfaces") or []:
        if shown >= 8:
            break
        addresses = ", ".join(iface.get("addresses") or []) or _missing(lang)
        name = iface.get("name") or "?"
        vpn = name in (info.get("vpn_interfaces") or [])
        label = theme.green(name) if vpn and theme.enabled else name
        lines.append(_kv(theme, label if not theme.enabled else name, _clip(addresses, 56, plain)))
        if vpn:
            # rewrite last line with a colored name is hard after _kv; append a marker instead
            lines[-1] = _kv(theme, name, theme.green(_clip(addresses, 48, plain) + "  vpn"))
        shown += 1
    extra = len(info.get("interfaces") or []) - shown
    if extra > 0:
        lines.append(_kv(theme, "", f"(+{extra})"))
    gateway = info.get("gateway") or t(lang, "none")
    dns = ", ".join(info.get("dns") or []) or t(lang, "none")
    vpn = ", ".join(info.get("vpn_interfaces") or []) or t(lang, "none")
    proxy = ", ".join(info.get("proxy_vars") or []) or t(lang, "none")
    lines.append(_kv(theme, t(lang, "field.gateway"), _clip(gateway, 56, plain)))
    lines.append(_kv(theme, t(lang, "field.dns"), _clip(dns, 56, plain)))
    vpn_shown = _clip(vpn, 56, plain)
    if info.get("vpn_interfaces"):
        vpn_shown = theme.green(vpn_shown)
    lines.append(_kv(theme, t(lang, "field.vpn"), vpn_shown))
    proxy_text = _clip(proxy, 56, plain)
    if info.get("proxy_vars"):
        proxy_text = theme.magenta(proxy_text + " = [REDACTED]")
    lines.append(_kv(theme, t(lang, "field.proxy"), proxy_text))
    if info.get("method"):
        lines.append(_kv(theme, t(lang, "field.method"), str(info.get("method"))))
    return lines


def _ports_panel(report, lang, theme, plain) -> list:
    info = (report.get("sections") or {}).get("ports") or {}
    lines = [_rule(t(lang, "probe.ports"), report["_width"], theme)]
    listeners = info.get("listeners") or []
    if not listeners:
        if info.get("status") == "ok":
            lines.append("  " + theme.green(t(lang, "listeners_none")))
        else:
            lines.append("  " + _status_word(info, lang, theme, False))
        return lines
    scope_label = {
        "wildcard": t(lang, "exposed"),
        "address": t(lang, "lan"),
        "loopback": t(lang, "local"),
    }
    for item in listeners[:12]:
        scope = item.get("scope") or "address"
        label = scope_label.get(scope, scope)
        text = f"{item.get('proto', 'tcp'):<3}  {format_endpoint(item.get('addr'), item.get('port'))}"
        if scope == "wildcard":
            colored = theme.red(text)
            tag = theme.red(label.ljust(8))
        elif scope == "address":
            colored = theme.yellow(text)
            tag = theme.yellow(label.ljust(8))
        else:
            colored = theme.green(text)
            tag = theme.green(label.ljust(8))
        lines.append(f"  {tag} {colored}")
    extra = len(listeners) - 12
    if extra > 0:
        lines.append(f"  (+{extra})")
    if info.get("method"):
        lines.append(_kv(theme, t(lang, "field.method"), str(info.get("method"))))
    return lines


def _env_panel(report, lang, theme, plain) -> list:
    info = (report.get("sections") or {}).get("env") or {}
    lines = [_rule(t(lang, "probe.env"), report["_width"], theme)]
    sensitive = info.get("sensitive") or []
    if sensitive:
        lines.append(
            _kv(
                theme,
                t(lang, "field.sensitive"),
                theme.magenta(f"{len(sensitive)}  = [REDACTED]"),
            )
        )
        for item in sensitive[:8]:
            lines.append("  " + theme.dim("· " if not plain else "- ") + f"{item.get('name')} = [REDACTED]")
        extra = len(sensitive) - 8
        if extra > 0:
            lines.append(f"    (+{extra})")
    else:
        lines.append(_kv(theme, t(lang, "field.sensitive"), theme.green(t(lang, "none"))))
    ssh = info.get("ssh") or {}
    if ssh.get("present"):
        bits = ssh.get("mode") or ""
        if ssh.get("world_readable") or ssh.get("world_writable"):
            bits = theme.red(bits or "open")
        elif ssh.get("group_readable"):
            bits = theme.yellow(bits or "group")
        else:
            bits = theme.green(bits or "ok")
        lines.append(_kv(theme, t(lang, "field.ssh"), f"{ssh.get('path')}  {bits}"))
        for key in (ssh.get("keys") or [])[:6]:
            mode = key.get("mode") or ""
            if key.get("world_readable") or key.get("world_writable"):
                mode = theme.red(mode)
            elif key.get("group_readable"):
                mode = theme.yellow(mode)
            lines.append(f"    {key.get('path')}  {mode}")
    else:
        lines.append(_kv(theme, t(lang, "field.ssh"), t(lang, "none")))
    histories = info.get("histories") or []
    if histories:
        parts = []
        for item in histories[:4]:
            mode = item.get("mode") or ""
            if item.get("world_readable") or item.get("world_writable"):
                mode = theme.red(mode)
            elif item.get("group_readable"):
                mode = theme.yellow(mode)
            parts.append(f"{item.get('path')} {mode}")
        lines.append(_kv(theme, t(lang, "field.history"), _clip("  ".join(parts), 60, plain)))
    secrets = info.get("secret_files") or []
    if secrets:
        parts = []
        for item in secrets[:4]:
            mode = item.get("mode") or ""
            if item.get("world_readable") or item.get("world_writable"):
                mode = theme.red(mode)
            parts.append(f"{item.get('path')} {mode}")
        lines.append(_kv(theme, t(lang, "field.secrets"), _clip("  ".join(parts), 60, plain)))
    return lines


def _firewall_panel(report, lang, theme, plain) -> list:
    info = (report.get("sections") or {}).get("firewall") or {}
    os_info = (report.get("sections") or {}).get("os") or {}
    lines = [_rule(t(lang, "probe.firewall"), report["_width"], theme)]
    if info.get("termux"):
        state = t(lang, "not_available")
        lines.append(_kv(theme, t(lang, "field.firewall"), theme.dim(state + "  termux")))
    elif info.get("active") is True:
        tool = info.get("tool") or ""
        lines.append(
            _kv(theme, t(lang, "field.firewall"), theme.green(f"{tool} {t(lang, 'active')}".strip()))
        )
    elif info.get("active") is False:
        tool = info.get("tool") or ""
        lines.append(
            _kv(theme, t(lang, "field.firewall"), theme.red(f"{tool} {t(lang, 'inactive')}".strip()))
        )
    else:
        lines.append(_kv(theme, t(lang, "field.firewall"), _status_word(info, lang, theme, False)))
    root = os_info.get("is_root")
    if root is True:
        priv = theme.red(t(lang, "root"))
    elif root is False:
        priv = theme.green(t(lang, "unprivileged"))
    else:
        priv = _missing(lang)
    lines.append(_kv(theme, t(lang, "field.privileges"), priv))
    return lines


def _browser_panel(report, lang, theme, plain) -> list:
    info = (report.get("sections") or {}).get("browser") or {}
    lines = [_rule(t(lang, "probe.browser"), report["_width"], theme)]
    browsers = info.get("browsers") or []
    if not browsers:
        if info.get("status") == "ok":
            lines.append("  " + theme.dim(t(lang, "browsers_none")))
        else:
            lines.append("  " + _status_word(info, lang, theme, False))
        return lines
    for item in browsers:
        note = t(lang, f"note.{item.get('note') or 'unknown'}")
        if item.get("privacy") is True:
            note = theme.green(note)
        elif item.get("privacy") is False:
            note = theme.yellow(note)
        else:
            note = theme.dim(note)
        lines.append(_kv(theme, item.get("name") or "?", note))
    return lines


def _score_panel(report, lang, theme, plain) -> list:
    width = report["_width"]
    score = report.get("score") or 0
    tier = report.get("risk_tier") or "LOW"
    label = tier_label(lang, tier)
    lines = [_rule(t(lang, "exposure"), width, theme)]
    bar = meter(score, 24, plain=plain)
    bar = theme.tier(tier, bar)
    score_text = theme.tier(tier, f"{score}/100")
    tier_text = theme.tier(tier, label)
    lines.append(f"  {theme.bold(t(lang, 'exposure').ljust(12))} {bar}  {score_text}  {tier_text}")
    ghost = report.get("ghost_id") or ""
    lines.append(_kv(theme, t(lang, "ghost_id"), theme.dim(ghost)))
    sources = ", ".join(report.get("ghost_id_sources") or []) or t(lang, "none")
    lines.append(_kv(theme, t(lang, "sources"), _clip(sources, 60, plain)))
    lines.append("  " + theme.dim(t(lang, "weights_hint")))
    return lines


def _findings_panel(report, lang, theme, plain) -> list:
    lines = ["", _rule(t(lang, "findings"), report["_width"], theme)]
    findings = list(report.get("findings") or [])
    family = report.get("family") or "other"
    distro = report.get("distro_id") or ""
    if not findings:
        lines.append("  " + theme.green(t(lang, "no_findings")))
        return lines
    tips = []
    for finding in findings:
        title, tip = describe(finding, lang, family, distro)
        sev = severity_label(lang, finding.severity)
        tag = theme.severity(finding.severity, f"[{sev}]")
        lines.append(f"  {tag} {title}  " + theme.dim(f"+{finding.points}"))
        if tip:
            tips.append(tip)
    lines.append("")
    lines.append(_rule(t(lang, "tips"), report["_width"], theme))
    if not tips:
        lines.append("  " + t(lang, "no_tips"))
        return lines
    seen = set()
    number = 1
    for tip in tips:
        if tip in seen:
            continue
        seen.add(tip)
        lines.append(f"  {number}. {tip}")
        number += 1
    return lines


def render_dashboard(report: dict, lang: str, theme: Theme, width: int = None) -> str:
    plain = not theme.enabled
    report = dict(report)
    report["_width"] = width or term_width()
    lines = []
    lines.extend(_banner(theme, report["_width"]))
    lines.append(theme.dim(t(lang, "tagline")) if theme.enabled else t(lang, "tagline"))
    lines.append("")
    lines.extend(_score_panel(report, lang, theme, plain))
    lines.append("")
    lines.extend(_readout(report, lang, theme))
    lines.append("")
    lines.extend(_os_panel(report, lang, theme, plain))
    lines.append("")
    lines.extend(_network_panel(report, lang, theme, plain))
    lines.append("")
    lines.extend(_ports_panel(report, lang, theme, plain))
    lines.append("")
    lines.extend(_env_panel(report, lang, theme, plain))
    lines.append("")
    lines.extend(_firewall_panel(report, lang, theme, plain))
    lines.append("")
    lines.extend(_browser_panel(report, lang, theme, plain))
    lines.extend(_findings_panel(report, lang, theme, plain))
    lines.append("")
    lines.append(theme.dim(t(lang, "disclaimer")) if theme.enabled else t(lang, "disclaimer"))
    return "\n".join(lines) + "\n"


def render_share(score: int, tier: str, lang: str, theme: Theme) -> str:
    """Score and tier only. No hostnames, addresses, users, or hashes."""
    line = share_line(lang, score, tier)
    plain = not theme.enabled
    rule_char = "-" if plain else "─"
    width = max(len(strip_ansi(line)), len(strip_ansi(t(lang, "share_title"))), 32)
    rule = rule_char * width
    title = t(lang, "share_title")
    note = t(lang, "share_note")
    if theme.enabled:
        rule = theme.cyan(rule)
        title = theme.bold(title)
        note = theme.dim(note)
        painted = theme.tier(tier, line)
    else:
        painted = line
    return "\n".join([rule, title, note, "", painted, rule]) + "\n"
