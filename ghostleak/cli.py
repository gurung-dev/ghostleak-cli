"""Argument parsing and scan orchestration."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from ghostleak import __version__
from ghostleak import safe
from ghostleak.i18n import normalize_lang
from ghostleak.probes import browser as browser_probe
from ghostleak.probes import env_audit
from ghostleak.probes import firewall as firewall_probe
from ghostleak.probes import network as network_probe
from ghostleak.probes import os_fingerprint
from ghostleak.probes import ports as ports_probe
from ghostleak.redact import scrub_text
from ghostleak.report import dumps_document, export_body
from ghostleak.score import (
    analyze,
    collect_ghost_signals,
    exposure_score,
    family_of,
    machine_ghost_id,
    risk_tier,
)
from ghostleak.ui import Theme, render_dashboard, render_share


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="ghostleak",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "GhostLeak CLI — local, offline device and privacy exposure scanner.\n"
            "Reads this machine only. Never opens a network connection. "
            "Never prints secret values."
        ),
        epilog=(
            "examples:\n"
            "  python3 ghostleak.py\n"
            "  python3 ghostleak.py --lang ne\n"
            "  python3 ghostleak.py --share\n"
            "  python3 ghostleak.py --json\n"
            "  python3 ghostleak.py --no-color --export report.md\n"
            "  python3 ghostleak.py --share --export share.txt\n"
        ),
    )
    parser.add_argument(
        "--lang",
        choices=("en", "ne"),
        default="en",
        help="UI language: en (English) or ne (Nepali). JSON risk_tier stays English.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a machine-readable JSON report. Secrets are redacted.",
    )
    parser.add_argument(
        "--share",
        action="store_true",
        help="Print only the score and risk tier. No host identifiers.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Plain ASCII output without ANSI colors or unicode meter glyphs.",
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="Write a private Markdown report, or JSON when FILE ends in .json.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ghostleak-cli {__version__}",
    )
    return parser.parse_args(argv)


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def use_color(args) -> bool:
    if getattr(args, "json", False) or getattr(args, "no_color", False):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return True


def build_report(lang: str = "en") -> dict:
    """Run every probe. One failing probe cannot abort the scan."""
    os_info = safe.guard_probe(os_fingerprint.collect)
    network = safe.guard_probe(network_probe.collect)
    ports = safe.guard_probe(ports_probe.collect)
    env = safe.guard_probe(env_audit.collect)
    firewall = safe.guard_probe(firewall_probe.collect)
    browsers = safe.guard_probe(browser_probe.collect)
    sections = {
        "os": os_info,
        "network": network,
        "ports": ports,
        "env": env,
        "firewall": firewall,
        "browser": browsers,
    }
    findings = analyze(sections)
    score = exposure_score(findings)
    tier = risk_tier(score)
    try:
        ghost, sources = machine_ghost_id(collect_ghost_signals())
    except Exception:
        ghost, sources = machine_ghost_id([])
    return {
        "version": __version__,
        "lang": normalize_lang(lang),
        "score": score,
        "risk_tier": tier,
        "ghost_id": ghost,
        "ghost_id_sources": sources,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "family": family_of(os_info),
        "distro_id": (os_info or {}).get("distro_id") or "",
        "sections": sections,
        "findings": findings,
    }


def _empty_report() -> dict:
    ghost, sources = machine_ghost_id([])
    return {
        "version": __version__,
        "lang": "en",
        "score": 0,
        "risk_tier": "LOW",
        "ghost_id": ghost,
        "ghost_id_sources": sources,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "family": "other",
        "distro_id": "",
        "sections": {},
        "findings": [],
    }


def main(argv=None) -> int:
    args = parse_args(argv)
    _utf8_stdio()
    lang = normalize_lang(args.lang)
    try:
        report = build_report(lang)
    except Exception:
        report = _empty_report()
    theme = Theme(enabled=use_color(args))
    try:
        if args.json:
            text = dumps_document(report, lang, share=bool(args.share))
        elif args.share:
            text = render_share(int(report["score"]), str(report["risk_tier"]), lang, theme)
        else:
            text = render_dashboard(report, lang, theme)
    except Exception:
        text = render_share(int(report.get("score") or 0), str(report.get("risk_tier") or "LOW"), lang, Theme(False))
    text = scrub_text(text)
    if not text.endswith("\n"):
        text += "\n"
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except BrokenPipeError:
        return 0
    if args.export:
        try:
            body = export_body(report, args.export, lang, share=bool(args.share))
            Path(args.export).write_text(body, encoding="utf-8")
        except OSError:
            sys.stderr.write("ghostleak: could not write the export file\n")
            return 1
        sys.stderr.write(f"ghostleak: wrote {args.export}\n")
    return 0
