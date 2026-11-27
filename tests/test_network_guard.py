"""The scanner must not import or call outbound network stacks."""

from __future__ import annotations

import ast
import io
import socket
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from ghostleak.cli import main
from ghostleak.safe import ALLOWED_COMMANDS
from tests.support import ROOT

BANNED_MODULES = {
    "urllib",
    "urllib.request",
    "http",
    "http.client",
    "http.server",
    "requests",
    "httpx",
    "aiohttp",
    "socket",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
    "xmlrpc.client",
}

BANNED_FUNCS = {
    "urlopen",
    "urlretrieve",
    "create_connection",
    "getaddrinfo",
    "gethostbyname",
    "os.system",
}


def _iter_sources():
    yield ROOT / "ghostleak.py"
    for path in (ROOT / "ghostleak").rglob("*.py"):
        yield path


class _Visitor(ast.NodeVisitor):
    def __init__(self):
        self.imports = []
        self.shell = False
        self.calls = []

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.append(node.module)
        self.generic_visit(node)

    def visit_Call(self, node):
        for keyword in node.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                self.shell = True
        if isinstance(node.func, ast.Name):
            self.calls.append(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            owner = node.func.value
            if (
                node.func.attr == "system"
                and isinstance(owner, ast.Name)
                and owner.id == "os"
            ):
                self.calls.append("os.system")
            else:
                self.calls.append(node.func.attr)
        self.generic_visit(node)


class NetworkGuardTests(unittest.TestCase):
    def test_source_has_no_network_imports(self):
        for path in _iter_sources():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            visitor = _Visitor()
            visitor.visit(tree)
            for name in visitor.imports:
                root = name.split(".", 1)[0]
                self.assertNotIn(root, BANNED_MODULES, f"{path} imports {name}")
                self.assertNotIn(name, BANNED_MODULES, f"{path} imports {name}")
            self.assertFalse(visitor.shell, f"{path} uses shell=True")
            for call in visitor.calls:
                self.assertNotIn(call, BANNED_FUNCS, f"{path} calls {call}")

    def test_allowlist_has_no_network_clients(self):
        banned = {
            "curl",
            "wget",
            "ping",
            "nc",
            "ncat",
            "netcat",
            "dig",
            "nslookup",
            "host",
            "ssh",
            "scp",
            "ftp",
            "telnet",
            "python",
            "python3",
        }
        self.assertTrue(ALLOWED_COMMANDS.isdisjoint(banned))

    def test_scan_does_not_connect_or_import_clients(self):
        before = set(sys.modules)
        calls = []
        real_run = __import__("subprocess").run

        def wrapped(argv, *args, **kwargs):
            if isinstance(argv, (list, tuple)) and argv:
                calls.append(os_basename(argv[0]))
            return real_run(argv, *args, **kwargs)

        def refuse(*_args, **_kwargs):
            raise AssertionError("socket connect attempted")

        with mock.patch("subprocess.run", wrapped), mock.patch(
            "socket.socket.connect", refuse
        ), mock.patch("socket.create_connection", refuse):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(["--json", "--no-color"])
        self.assertEqual(code, 0)
        json_ok = stdout.getvalue().lstrip().startswith("{")
        self.assertTrue(json_ok)
        for name in calls:
            self.assertIn(name, ALLOWED_COMMANDS, name)
        for module in ("urllib.request", "http.client", "requests", "httpx", "socket"):
            if module not in before and module != "socket":
                self.assertNotIn(module, sys.modules)


def os_basename(value) -> str:
    text = str(value).replace("\\", "/")
    return text.rsplit("/", 1)[-1]


if __name__ == "__main__":
    unittest.main()
