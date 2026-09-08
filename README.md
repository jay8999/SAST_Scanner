# SAST_Scanner
A lightweight, zero dependency Static Application Security Testing (SAST) command line tool written in Python designed to detect hardcoded API keys, sensitive credentials, and dangerous code patterns across source codebases.

# Features:

Regex-Powered Detection: Identifies high-risk artifacts including AWS Access Keys, generic API token assignments, and dangerous function sinks (eval(), pickle.load).

Intelligent Directory Filtering: Automatically bypasses non-source and dependency directories (e.g., .git, node_modules, venv, __pycache__, dist) to minimize noise and scan overhead.

Structured JSON Reporting: Serializes findings with exact file paths, line numbers, vulnerability classifications, and matched code snippets into a standardized machine-readable schema.

Pipeline-Ready Architecture: Built with clean CLI arguments via argparse, making it ideal for integration into automated security gates and CI/CD pipelines.

# Quick Start

Clone the repository and execute the scanner against your target codebase directly from the terminal.

```
git clone https://github.com/your-username/codesec-scanner.git
cd codesec-scanner
python scanner.py /path/to/target -o scan_results.json
```

# CLI Usage Options

```
python scanner.py --help
```

target: The local directory or file path you want to analyze.

-o, --output: Optional flag to specify a custom filename for the generated JSON report (defaults to scan_results.json).

# Sample JSON Output

```
{
  "scan_timestamp": "2026-03-06T14:30:00Z",
  "total_findings": 1,
  "vulnerabilities": [
    {
      "file_path": "vulnerable_sample.py",
      "line_number": 2,
      "vulnerability_type": "AWS Access Key",
      "matched_snippet": "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\""
    }
  ]
}
```

# Verifying with Test Data

The repository includes a vulnerable_sample.py file containing intentional security flaws to verify that the scanner operates correctly:

```
python scanner.py vulnerable_sample.py -o test_results.json
```

# Project Motivation

Built as a practical utility for code reviews and security auditing. Whether performing white-box penetration testing or setting up automated defensive checks to prevent accidental credential leakage, this tool bridges the gap between development workflows and application security. Feel free to contact if you have any ideas for future implementation.
