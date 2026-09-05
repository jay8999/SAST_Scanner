import argparse # to let us type commands in our terminal.
import json # to write our findings into a neat tidy report card.
import os # so python can walk around folders like a person exploring a house.
import re # for regular expressions that can help find api keys and other common keys quickly.
from datetime import datetime # to let the output have the date and time it was created.

# PATTERNS dictionary holds our api key and other important commonly used passwords/functions that shouldnt be hardcoded.
PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Generic API Key": (
        r"(?i)api[_-]?key['\"']?\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{16,40}['\"']"
    ),
    "Insecure Eval": r"\beval\s*\(",
    "Insecure Pickle": r"pickle\.load",
}

# Dictionary full of common third party github folders that our scanner can safely ignore.
IGNORE_DIRS = {".git", "node_modules", "venv", "__pycache__", "dist", "build"}

# The scan_file function is responsible for reading every file and checking the contents against our regular expressions. If it spots a match, it writes down the file name, the line number, and what it found onto a notepad.
def scan_file(file_path):
  findings = []
  try:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
      for line_num, line in enumerate(f, 1):
        for vuln_type, pattern in PATTERNS.items():
          if re.search(pattern, line):
            findings.append({
                "file_path": file_path,
                "line_number": line_num,
                "vulnerability_type": vuln_type,
                "matched_snippet": line.strip(),
            })
  except Exception as e:
    print(f"Could not read {file_path}: {e}")
  return findings

# The scan codebase function uses os.walk() to open every folder in a project folder. Using the IGNORE_DIRS dictionary, it ignores messy folders like node_modules and .git so it doesnt waste time scanning other people's pre made code files.
def scan_codebase(target_dir):
  all_findings = []
  for root, dirs, files in os.walk(target_dir):
    dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
    for file in files:
      file_path = os.path.join(root, file)
      all_findings.extend(scan_file(file_path))
  return all_findings

# The main function brings everything together and parses all of our findings into a neat document and saves it as a scan_results.json file.
def main():
  parser = argparse.ArgumentParser(description="Simple Code Security Scanner")
  parser.add_argument("target", help="Path to the directory you want to scan")
  parser.add_argument(
      "-o", "--output", default="scan_results.json", help="Output JSON file name"
  )

  args = parser.parse_args()
  findings = scan_codebase(args.target)

  report = {
      "scan_timestamp": datetime.utcnow().isoformat() + "Z",
      "total_findings": len(findings),
      "vulnerabilities": findings,
  }

  with open(args.output, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4)

  print(f"Scan complete! Results saved to {args.output}")


if __name__ == "__main__":
  main()
