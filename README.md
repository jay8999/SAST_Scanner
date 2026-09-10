# SAST_Scanner

A lightweight, zero dependency Static Application Security Testing (SAST) command line tool written in Python, designed to detect hardcoded API keys, sensitive credentials, and dangerous code patterns across source codebases.

# Features

**Hybrid Detection Engine:** Python files (`.py`) are analyzed with Python's built-in `ast` module, so the scanner understands real code structure instead of just matching text. Every other file type falls back to regex matching.

**Severity Ratings:** Every finding is tagged High, Medium, or Low, and the `--severity` flag lets you filter the report down to only what matters for the check you're running.

**Intelligent Directory Filtering:** Automatically bypasses non-source and dependency directories (e.g., `.git`, `node_modules`, `venv`, `__pycache__`, `dist`) to minimize noise and scan overhead.

**Structured JSON Reporting:** Serializes findings with exact file paths, line numbers, vulnerability classifications, severity, matched code snippets, and which engine (`ast` or `regex`) caught them.

**CI/CD Ready:** Ships with a GitHub Actions workflow (`.github/workflows/sast.yml`) that runs the scanner on every push and pull request, uploads the JSON report as a build artifact, and fails the build if any High severity finding is detected.

# Architecture

The scanner is built around two detection engines that share one output format:

- **AST engine (`scan_file_ast`)** — used for any `.py` file. It parses the file into a syntax tree and only flags things that are actually happening in code: a real call to `eval()`/`exec()`/`pickle.load()`, or a real assignment of a hardcoded string to a variable whose name looks like a secret (`api_key`, `token`, `password`, etc.). If the file fails to parse (e.g. it's not valid Python), the scanner falls back to the regex engine for that file instead of silently reporting nothing.
- **Regex engine (`scan_file_regex`)** — the original line-by-line matcher. It's the only option for non-Python files (JS, YAML, `.env`, config files, and so on), where there's no ready-made parser to lean on.

`scan_file()` decides which engine handles a given file, and `scan_codebase()` walks the target (or scans it directly, if it's a single file) and merges everything into one findings list. `main()` then filters that list by `--severity` before writing the JSON report.

```
scan_codebase()
 ├─ target is a file  → scan_file(target)
 └─ target is a dir   → os.walk(), skip IGNORE_DIRS, scan_file() per file
      scan_file()
       ├─ .py file → scan_file_ast()   (falls back to regex on parse failure)
       └─ other    → scan_file_regex()
```

# Why AST instead of just regex?

Regex is fast and works on any language, but it can't tell code from a comment, a docstring, or a string literal. A line like `# used to call eval() here, removed it` or `message = "don't eval(x)"` would trip the old regex-only scanner even though there's no actual vulnerability. That's a false positive, and a scanner that cries wolf gets ignored or disabled.

The `ast` module parses Python source into its actual syntax tree, so the scanner can ask more precise questions: *is this string literally being passed to a call to `eval`?* rather than *does the word "eval" appear on this line?* The same logic applies to hardcoded secrets — the AST engine only flags a string when it's genuinely assigned to a suspiciously-named variable, not whenever a matching pattern shows up anywhere in the file.

Regex isn't going away, though: it's still the only practical way to check non-Python files, and it's a safe fallback if a `.py` file can't be parsed (e.g. Python 2 syntax, or a syntax error). The two engines are complementary rather than either/or, which is why both still exist side by side.

# Quick Start

Clone the repository and run the scanner against your target codebase directly from the terminal.

```
git clone https://github.com/your-username/SAST_Scanner.git
cd SAST_Scanner
python SAST_Scanner.py /path/to/target -o scan_results.json
```

# CLI Usage Options

```
python SAST_Scanner.py --help
```

- `target`: The local directory or file path you want to analyze.
- `-o, --output`: Optional flag to specify a custom filename for the generated JSON report (defaults to `scan_results.json`).
- `--severity`: Minimum severity to include in the report — `Low`, `Medium`, or `High` (defaults to `Low`, which shows everything). Use `--severity High` to see only the findings worth blocking a build over.

# Sample JSON Output

```
{
  "scan_timestamp": "2026-03-06T14:30:00Z",
  "severity_filter": "Low",
  "total_findings": 1,
  "vulnerabilities": [
    {
      "file_path": "vulnerable_sample.py",
      "line_number": 2,
      "vulnerability_type": "AWS Access Key",
      "severity": "High",
      "matched_snippet": "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"",
      "detection_method": "ast"
    }
  ]
}
```

# Verifying with Test Data

The repository includes a `vulnerable_sample.py` file containing intentional security flaws to verify that the scanner operates correctly:

```
python SAST_Scanner.py vulnerable_sample.py -o test_results.json
```

# Running as a GitHub Action

`.github/workflows/sast.yml` runs the scanner automatically on every push and pull request to `main` (and can also be triggered manually from the Actions tab). It:

1. Checks out the repo and sets up Python.
2. Runs the scanner against the whole repository.
3. Uploads `scan_results.json` as a downloadable build artifact, even if the job later fails.
4. Fails the build if any **High** severity finding is present, so real risks (hardcoded AWS keys, `eval()`, `pickle.load()`) block a merge instead of quietly sitting in a report nobody reads.

To adjust what fails the build, edit the severity check step in the workflow file — for example, change it to fail on Medium and above too.

# Project Motivation

Built as a practical utility for code reviews and security auditing. Whether performing white-box penetration testing or setting up automated defensive checks to prevent accidental credential leakage, this tool bridges the gap between development workflows and application security. Feel free to contact if you have any ideas for future implementation.
