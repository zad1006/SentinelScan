# SentinelScan

A small, dependency-free Python static security scanner built as a cybersecurity portfolio project.

## Features
- Flags literal strings assigned to secret-like variable names
- Flags `eval()` and `exec()` calls
- Flags subprocess calls using `shell=True`
- Flags world-writable Python files on POSIX systems
- Outputs readable terminal findings and optional JSON reports
- Includes automated tests and a deliberately vulnerable sample

## Requirements
Python 3.9 or newer. No third-party dependencies.

## Quick start
From the project root:

```bash
python -m sentinelscan examples --json report.json
python -m unittest discover -s tests -v
```

To scan your own code:

```bash
python -m sentinelscan /path/to/your/python/project --json results.json
```

## Limitations
This is a lightweight educational tool, **not** a complete security audit. It detects a small set of patterns and may produce false positives or miss real vulnerabilities. Findings should be reviewed manually. It only scans Python files and skips common dependency directories. Avoid publishing real secrets in code or reports.

## Suggested extensions
- GitHub Actions CI workflow
- SARIF output for GitHub Code Scanning
- More AST rules and configuration support
- Documentation of false positives and benchmark samples

## Resume wording (after you have tested and understood the project)
**SentinelScan — Python Static Security Scanner** | Python, AST, JSON, unittest
- Built a command-line static analysis tool to flag hardcoded secrets, dynamic code execution, and risky subprocess calls in Python projects.
- Implemented structured JSON security reports and automated tests to validate detection rules.
