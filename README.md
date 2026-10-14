# 🛡️ SentinelScan — Python Static Security Scanner

A lightweight Python-based static security analysis tool designed to identify potentially insecure coding practices and security vulnerabilities in Python projects.

SentinelScan analyzes source code without executing it, helping developers identify security risks during development.

## Key Features

- **Hardcoded Credential Detection:** Identifies potential passwords, API keys, and secrets stored directly in source code.
- **Unsafe Code Execution:** Detects potentially dangerous `eval()` and `exec()` calls.
- **Subprocess Security:** Flags subprocess calls using `shell=True`.
- **File Permission Analysis:** Identifies world-writable Python files on supported POSIX systems.
- **JSON Security Reports:** Generates structured reports containing findings and severity levels.
- **Automated Testing:** Includes unit tests to validate scanner functionality.

## Technologies Used

- Python 3.9+
- Abstract Syntax Trees (AST)
- Regular Expressions
- JSON
- Python unittest
- Command-Line Interface (CLI)

No third-party dependencies required.

## Installation

Clone the repository:

```bash
git clone https://github.com/zad1006/SentinelScan.git
```

Navigate into the project directory:

```bash
cd SentinelScan
```

## Usage

**Scan the included vulnerable example:**

```bash
python -m sentinelscan examples --json report.json
```

**Scan your own Python project:**

```bash
python -m sentinelscan /path/to/project --json results.json
```

**Run automated tests:**

```bash
python -m unittest discover -s tests -v
```

## Example Security Scan Results

The following output was produced when scanning the included intentionally vulnerable example:

```text
[HIGH] examples\vulnerable_demo.py:2 HARDCODED_SECRET
[HIGH] examples\vulnerable_demo.py:3 DYNAMIC_EXECUTION

Found 2 potential issue(s).
Report saved to report.json
```

### Detected Security Issues

| Vulnerability | Severity | Description |
|---|---|---|
| Hardcoded Secret | HIGH | Potential API key stored directly in source code |
| Dynamic Execution | HIGH | `eval()` call that may execute untrusted code |

## Project Structure

```text
SentinelScan/
├── sentinelscan/
│   ├── __init__.py
│   ├── __main__.py
│   └── scanner.py
├── tests/
│   └── test_scanner.py
├── examples/
│   └── vulnerable_demo.py
├── README.md
├── .gitignore
└── example_report.json
```

## Testing

SentinelScan includes automated unit tests for its security detection functionality.

The scanner was also manually tested against the included vulnerable Python example, successfully identifying two potential security issues and generating a JSON report.

## Security Considerations

SentinelScan is an educational static analysis project, not a replacement for a professional security audit. It may produce false positives or miss vulnerabilities. All findings should be manually reviewed.

## Future Improvements

- GitHub Actions continuous integration
- Additional security detection rules
- SARIF reporting for GitHub Code Scanning
- Configurable scanning policies

## Author

**Zachariah Djedid**

Cybersecurity Student — Slippery Rock University

GitHub: https://github.com/zad1006
