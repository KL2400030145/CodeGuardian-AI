import ast
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


RULES = [
    ("CG001", "Use of eval()", "high", r"\beval\s*\(", "Avoid eval(); it can execute attacker-controlled input."),
    ("CG002", "Use of exec()", "high", r"\bexec\s*\(", "Avoid exec(); it can execute dynamically supplied code."),
    ("CG003", "Possible hard-coded credential", "high", r"(?i)(password|passwd|api_key|secret)\s*=\s*['\"][^'\"]{4,}['\"]", "Move credentials to environment variables or a secret manager."),
    ("CG004", "Subprocess with shell=True", "high", r"subprocess\.(run|Popen|call)\s*\([^)]*shell\s*=\s*True", "Avoid shell=True with untrusted input; pass an argument list."),
    ("CG005", "Disabled TLS verification", "medium", r"verify\s*=\s*False", "Do not disable TLS certificate verification in production."),
    ("CG006", "Weak hash algorithm", "medium", r"hashlib\.(md5|sha1)\s*\(", "Use a modern hash for integrity; use a password hashing function for passwords."),
]


class ScannerExecutionError(RuntimeError):
    pass


def scan_source(filename: str, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = source.splitlines()
    for rule_id, title, severity, pattern, recommendation in RULES:
        for match in re.finditer(pattern, source):
            line = source.count("\n", 0, match.start()) + 1
            findings.append(
                {
                    "rule_id": rule_id,
                    "title": title,
                    "severity": severity,
                    "file": filename,
                    "line": line,
                    "snippet": lines[line - 1][:240] if line <= len(lines) else "",
                    "description": recommendation,
                    "recommendation": recommendation,
                    "source": "CodeGuardian",
                }
            )
    try:
        ast.parse(source)
    except SyntaxError as exc:
        findings.append(
            {
                "rule_id": "CG000",
                "title": "Python syntax error",
                "severity": "low",
                "file": filename,
                "line": exc.lineno or 1,
                "snippet": (exc.text or "").strip()[:240],
                "description": exc.msg,
                "recommendation": "Fix the syntax error and scan again.",
                "source": "Python AST",
            }
        )
    return findings


def _run_json_command(command: list[str], timeout: int, scanner_name: str) -> Any:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ScannerExecutionError(f"{scanner_name} timed out.") from exc
    except OSError as exc:
        raise ScannerExecutionError(f"{scanner_name} could not be started.") from exc
    try:
        payload = json.loads(proc.stdout or "")
    except json.JSONDecodeError as exc:
        detail = (proc.stderr or "No valid JSON output was produced.").strip()[:300]
        raise ScannerExecutionError(f"{scanner_name} failed: {detail}") from exc
    if proc.returncode not in (0, 1):
        detail = (proc.stderr or "Scanner exited unexpectedly.").strip()[:300]
        raise ScannerExecutionError(f"{scanner_name} failed: {detail}")
    return payload


def _bandit(paths: list[str], path_names: dict[str, str]) -> list[dict[str, Any]]:
    payload = _run_json_command([sys.executable, "-m", "bandit", "-f", "json", "-q", *paths], 45, "Bandit")
    return [
        {
            "rule_id": item.get("test_id", "BANDIT"),
            "title": item.get("issue_text", "Bandit finding"),
            "severity": item.get("issue_severity", "MEDIUM").lower(),
            "file": path_names.get(item.get("filename", ""), Path(item.get("filename", "")).name),
            "line": item.get("line_number", 1),
            "snippet": item.get("code", "").strip()[:240],
            "description": item.get("issue_text", ""),
            "recommendation": item.get("more_info", "Review the Bandit guidance for this rule."),
            "source": "Bandit",
        }
        for item in payload.get("results", [])
    ]


def _ruff(paths: list[str], path_names: dict[str, str]) -> list[dict[str, Any]]:
    payload = _run_json_command(
        [sys.executable, "-m", "ruff", "check", "--output-format", "json", *paths],
        45,
        "Ruff",
    )
    findings: list[dict[str, Any]] = []
    for item in payload:
        code = item.get("code") or "RUFF"
        severity = "medium" if code.startswith(("S", "B")) else "low"
        findings.append(
            {
                "rule_id": code,
                "title": item.get("message", "Ruff finding"),
                "severity": severity,
                "file": path_names.get(item.get("filename", ""), Path(item.get("filename", "")).name),
                "line": item.get("location", {}).get("row", 1),
                "snippet": "",
                "description": item.get("message", ""),
                "recommendation": "Review the Ruff diagnostic and apply the suggested fix when appropriate.",
                "source": "Ruff",
            }
        )
    return findings


def _radon(entries: dict[str, str]) -> list[dict[str, Any]]:
    from radon.complexity import cc_visit

    findings: list[dict[str, Any]] = []
    for filename, source in entries.items():
        try:
            blocks = cc_visit(source)
        except (SyntaxError, ValueError):
            continue
        lines = source.splitlines()
        for block in blocks:
            if block.complexity < 15:
                continue
            findings.append(
                {
                    "rule_id": "CG-RADON-COMPLEXITY",
                    "title": f"High cyclomatic complexity: {block.name}",
                    "severity": "medium" if block.complexity >= 20 else "low",
                    "file": filename,
                    "line": block.lineno,
                    "snippet": lines[block.lineno - 1][:240] if block.lineno <= len(lines) else "",
                    "description": f"{block.name} has cyclomatic complexity {block.complexity}.",
                    "recommendation": "Consider extracting smaller functions and reducing branching.",
                    "source": "Radon",
                }
            )
    return findings


def _semgrep(paths: list[str], path_names: dict[str, str]) -> list[dict[str, Any]]:
    payload = _run_json_command(
        ["semgrep", "--quiet", "--config", "p/python", "--json", *paths],
        90,
        "Semgrep",
    )
    findings: list[dict[str, Any]] = []
    for item in payload.get("results", []):
        extra = item.get("extra", {})
        severity = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(
            extra.get("severity", "INFO"), "low"
        )
        findings.append(
            {
                "rule_id": item.get("check_id", "SEMGREP"),
                "title": extra.get("message", "Semgrep finding"),
                "severity": severity,
                "file": path_names.get(item.get("path", ""), Path(item.get("path", "")).name),
                "line": item.get("start", {}).get("line", 1),
                "snippet": extra.get("lines", "").strip()[:240],
                "description": extra.get("message", ""),
                "recommendation": "Review the Semgrep rule guidance and validate the suggested remediation.",
                "source": "Semgrep",
            }
        )
    return findings


def analyze_files(entries: dict[str, str]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    findings = [finding for name, source in entries.items() for finding in scan_source(name, source)]
    statuses = {"CodeGuardian": "completed"}
    paths: list[str] = []
    path_names: dict[str, str] = {}

    with tempfile.TemporaryDirectory(prefix="cg_scan_") as tmp:
        for index, (name, source) in enumerate(entries.items()):
            path = os.path.join(tmp, f"source_{index}.py")
            Path(path).write_text(source, encoding="utf-8")
            paths.append(path)
            path_names[path] = name

        for scanner, module, run in (
            ("Bandit", "bandit", _bandit),
            ("Ruff", "ruff", _ruff),
        ):
            if importlib.util.find_spec(module) is None:
                statuses[scanner] = "not_installed"
                continue
            try:
                findings.extend(run(paths, path_names))
                statuses[scanner] = "completed"
            except ScannerExecutionError as exc:
                statuses[scanner] = f"failed: {exc}"

        try:
            findings.extend(_radon(entries))
            statuses["Radon"] = "completed"
        except ImportError:
            statuses["Radon"] = "not_installed"

        if shutil.which("semgrep"):
            try:
                findings.extend(_semgrep(paths, path_names))
                statuses["Semgrep"] = "completed"
            except ScannerExecutionError as exc:
                statuses["Semgrep"] = f"failed: {exc}"
        else:
            statuses["Semgrep"] = "not_installed"

    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in findings:
        identity = (
            finding["rule_id"],
            finding["file"],
            finding["line"],
            finding["title"],
        )
        unique.setdefault(identity, finding)
    sorted_findings = sorted(
        unique.values(),
        key=lambda item: {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }.get(item["severity"], 5),
    )
    return sorted_findings, statuses
