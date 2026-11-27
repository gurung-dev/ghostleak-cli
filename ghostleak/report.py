"""JSON and Markdown reports. Share mode keeps only score and tier."""

from __future__ import annotations

import json

from ghostleak import __version__
from ghostleak.i18n import describe, share_line, t, tier_label
from ghostleak.redact import sanitize_tree, scrub_text
from ghostleak.score import TIERS, WEIGHTS


def share_document(score: int, tier: str, lang: str) -> dict:
    return {
        "score": int(score),
        "risk_tier": tier,
        "summary": share_line(lang, int(score), tier),
    }


def _finding_dict(finding, lang: str, family: str, distro_id: str) -> dict:
    title, tip = describe(finding, lang, family, distro_id)
    return {
        "code": finding.code,
        "severity": finding.severity,
        "points": finding.points,
        "title": title,
        "tip": tip,
    }


def document(report: dict, lang: str) -> dict:
    """Private machine-readable report. Secret values are not included."""
    family = report.get("family") or "other"
    distro = report.get("distro_id") or ""
    sections = report.get("sections") or {}
    payload = {
        "tool": "ghostleak-cli",
        "version": __version__,
        "offline": True,
        "secrets_redacted": True,
        "network_calls": False,
        "lang": lang,
        "score": report.get("score"),
        "risk_tier": report.get("risk_tier"),
        "risk_tier_label": tier_label(lang, report.get("risk_tier") or "LOW"),
        "ghost_id": report.get("ghost_id"),
        "ghost_id_sources": list(report.get("ghost_id_sources") or []),
        "scanned_at": report.get("scanned_at"),
        "family": family,
        "os": sections.get("os") or {},
        "network": sections.get("network") or {},
        "ports": sections.get("ports") or {},
        "environment": sections.get("env") or {},
        "firewall": sections.get("firewall") or {},
        "browsers": sections.get("browser") or {},
        "findings": [
            _finding_dict(finding, lang, family, distro)
            for finding in report.get("findings") or []
        ],
        "weights": WEIGHTS,
        "tiers": TIERS,
    }
    return sanitize_tree(payload)


def dumps_document(report: dict, lang: str, environ=None, share: bool = False) -> str:
    if share:
        payload = share_document(report.get("score") or 0, report.get("risk_tier") or "LOW", lang)
    else:
        payload = document(report, lang)
    raw = json.dumps(payload, ensure_ascii=False, indent=2)
    cleaned = scrub_text(raw, environ)
    try:
        json.loads(cleaned)
    except json.JSONDecodeError:
        return raw + "\n"
    if not cleaned.endswith("\n"):
        cleaned += "\n"
    return cleaned


def _bullet_block(title: str, rows: list) -> list:
    lines = [f"## {title}", ""]
    if not rows:
        lines.append("- (empty)")
        lines.append("")
        return lines
    for key, value in rows:
        if value is None or value == "":
            shown = "[NOT AVAILABLE]"
        else:
            shown = value
        lines.append(f"- **{key}:** {shown}")
    lines.append("")
    return lines


def markdown_report(report: dict, lang: str) -> str:
    family = report.get("family") or "other"
    distro = report.get("distro_id") or ""
    sections = report.get("sections") or {}
    os_info = sections.get("os") or {}
    network = sections.get("network") or {}
    ports = sections.get("ports") or {}
    env = sections.get("env") or {}
    firewall = sections.get("firewall") or {}
    browsers = sections.get("browser") or {}
    lines = [
        "# GhostLeak CLI report",
        "",
        f"- **Score:** {report.get('score')}/100",
        f"- **Risk tier:** {report.get('risk_tier')} ({tier_label(lang, report.get('risk_tier') or 'LOW')})",
        f"- **Machine Ghost ID:** `{report.get('ghost_id')}`",
        "- **Ghost ID sources:** " + ", ".join(report.get("ghost_id_sources") or []),
        f"- **Family:** {family}",
        f"- **Scanned:** {report.get('scanned_at')}",
        "",
        t(lang, "disclaimer"),
        "",
    ]
    iface_bits = []
    for iface in network.get("interfaces") or []:
        addrs = ", ".join(iface.get("addresses") or []) or "-"
        iface_bits.append(f"{iface.get('name')} {addrs}")
    listener_bits = [
        f"{item.get('scope')} {item.get('proto')} {item.get('addr')}:{item.get('port')}"
        for item in (ports.get("listeners") or [])
    ]
    sensitive_bits = [
        f"{item.get('name')} = [REDACTED]" for item in (env.get("sensitive") or [])
    ]
    lines.extend(
        _bullet_block(
            t(lang, "probe.os"),
            [
                ("system", os_info.get("system")),
                ("distro", os_info.get("distro")),
                ("kernel", os_info.get("kernel")),
                ("arch", os_info.get("arch")),
                ("cpu", os_info.get("cpu_model")),
                ("cores", os_info.get("cpu_cores")),
                ("hostname", os_info.get("hostname")),
                ("termux", os_info.get("termux")),
                ("timezone", os_info.get("timezone")),
                ("locale", os_info.get("locale")),
                ("python", os_info.get("python")),
            ],
        )
    )
    lines.extend(
        _bullet_block(
            t(lang, "probe.network"),
            [
                ("interfaces", "; ".join(iface_bits) or None),
                ("gateway", network.get("gateway")),
                ("dns", ", ".join(network.get("dns") or []) or None),
                ("vpn", ", ".join(network.get("vpn_interfaces") or []) or None),
                ("proxy", ", ".join(network.get("proxy_vars") or []) or None),
                ("status", network.get("status")),
            ],
        )
    )
    lines.extend(
        _bullet_block(
            t(lang, "probe.ports"),
            [
                ("method", ports.get("method")),
                ("listeners", "; ".join(listener_bits) or None),
                ("status", ports.get("status")),
            ],
        )
    )
    lines.extend(
        _bullet_block(
            t(lang, "probe.env"),
            [
                ("sensitive", "; ".join(sensitive_bits) or None),
                ("ssh", (env.get("ssh") or {}).get("path")),
                ("ssh mode", (env.get("ssh") or {}).get("mode")),
                (
                    "history",
                    "; ".join(
                        f"{item.get('path')} {item.get('mode')}" for item in (env.get("histories") or [])
                    )
                    or None,
                ),
            ],
        )
    )
    lines.extend(
        _bullet_block(
            t(lang, "probe.firewall"),
            [
                ("tool", firewall.get("tool")),
                ("active", firewall.get("active")),
                ("detail", firewall.get("detail")),
                ("status", firewall.get("status")),
                ("root", os_info.get("is_root")),
            ],
        )
    )
    browser_bits = [
        f"{item.get('name')}: {item.get('note')}" for item in (browsers.get("browsers") or [])
    ]
    lines.extend(
        _bullet_block(
            t(lang, "probe.browser"),
            [("browsers", "; ".join(browser_bits) or None), ("status", browsers.get("status"))],
        )
    )
    lines.append(f"## {t(lang, 'findings')}")
    lines.append("")
    findings = list(report.get("findings") or [])
    if not findings:
        lines.append(t(lang, "no_findings"))
        lines.append("")
    for finding in findings:
        title, tip = describe(finding, lang, family, distro)
        lines.append(f"### [{finding.severity.upper()}] {title}")
        lines.append("")
        lines.append(f"+{finding.points} points.")
        lines.append("")
        lines.append(tip)
        lines.append("")
    lines.append("## Weights")
    lines.append("")
    lines.append("| Signal | Points each | Cap | Meaning |")
    lines.append("| --- | ---: | ---: | --- |")
    for row in WEIGHTS:
        lines.append(
            f"| `{row['code']}` | {row['points']} | {row['cap']} | {row['summary']} |"
        )
    lines.append("")
    lines.append("Tiers: 0-24 LOW, 25-49 MODERATE, 50-74 HIGH, 75-100 CRITICAL. Total capped at 100.")
    lines.append("")
    lines.append("_Generated locally by GhostLeak CLI. No network calls. Secret values redacted._")
    lines.append("")
    return "\n".join(lines)


def share_markdown(score: int, tier: str, lang: str) -> str:
    line = share_line(lang, score, tier)
    return "\n".join(
        [
            "# GhostLeak CLI safe share",
            "",
            line,
            "",
            "100% offline. No host identifiers, addresses, usernames, or hashes.",
            "",
        ]
    )


def export_body(report: dict, path: str, lang: str, share: bool, environ=None) -> str:
    suffix = ""
    if path:
        dot = str(path).rfind(".")
        if dot != -1:
            suffix = str(path)[dot:].lower()
    if share:
        if suffix == ".json":
            body = dumps_document(report, lang, environ=environ, share=True)
        else:
            body = scrub_text(
                share_markdown(report.get("score") or 0, report.get("risk_tier") or "LOW", lang),
                environ,
            )
    elif suffix == ".json":
        body = dumps_document(report, lang, environ=environ, share=False)
    else:
        body = scrub_text(markdown_report(report, lang), environ)
    if not body.endswith("\n"):
        body += "\n"
    return body
