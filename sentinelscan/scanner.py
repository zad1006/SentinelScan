"""Conservative educational static scanner. Findings require human review."""
import ast
import json
import os
import re
from pathlib import Path

SECRET_NAME = re.compile(r'(password|passwd|api[_-]?key|secret|access[_-]?token)', re.I)
SKIP_DIRS = {'.git', '.venv', 'venv', '__pycache__', 'node_modules', '.pytest_cache'}


def finding(path, line, rule, severity, message):
    return {'file': str(path), 'line': line, 'rule': rule,
            'severity': severity, 'message': message}


def scan_file(path):
    path = Path(path)
    results = []
    try:
        source = path.read_text(encoding='utf-8')
    except (OSError, UnicodeError):
        return results
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return [finding(path, 0, 'PARSE_ERROR', 'info', 'Could not parse Python file')]
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
                for target in targets:
                    if isinstance(target, ast.Name) and SECRET_NAME.search(target.id):
                        results.append(finding(path, node.lineno, 'HARDCODED_SECRET', 'high',
                            f'Possible hardcoded secret in variable {target.id}; verify manually'))
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {'eval', 'exec'}:
                results.append(finding(path, node.lineno, 'DYNAMIC_EXECUTION', 'high',
                    f'{node.func.id}() can execute untrusted code'))
            if isinstance(node.func, ast.Attribute) and node.func.attr in {'run', 'Popen', 'call', 'check_output', 'check_call'}:
                if any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                    results.append(finding(path, node.lineno, 'SHELL_TRUE', 'medium',
                        'Subprocess with shell=True needs careful input handling'))
    if os.name == 'posix':
        try:
            if path.stat().st_mode & 0o002:
                results.append(finding(path, 0, 'WORLD_WRITABLE', 'medium',
                    'File is writable by other users'))
        except OSError:
            pass
    return results


def scan_directory(root):
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(root)
    if root.is_file():
        return scan_file(root) if root.suffix == '.py' else []
    findings = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name.endswith('.py'):
                findings.extend(scan_file(Path(directory) / name))
    return findings


def report(root):
    findings = scan_directory(root)
    return {'tool': 'SentinelScan', 'target': str(root), 'finding_count': len(findings),
            'findings': findings}
