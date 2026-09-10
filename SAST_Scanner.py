import argparse  # to let us type commands in our terminal.
import ast  # to actually understand Python code as code, not just text.
import json  # to write our findings into a neat tidy report card.
import os  # so python can walk around folders like a person exploring a house.
import re  # for regular expressions that can help find api keys and other common keys quickly.
from datetime import datetime  # to let the output have the date and time it was created.

# ---------------------------------------------------------------------------
# WHAT IS THIS FILE?
# This is a very small "SAST" (Static Application Security Testing) tool.
# "Static" means we never run the target code - we just read it, the same way
# you'd read a book, looking for lines that look dangerous or leak secrets.
# ---------------------------------------------------------------------------

# PATTERNS dictionary holds our vulnerability signatures - basically our "cheat
# sheet" of things to look out for. Each entry has two parts:
#   "regex"    -> a regular expression (a search pattern) that matches the
#                 dangerous text we're hunting for.
#   "severity" -> how bad it is if we find it: "High", "Medium", or "Low".
# Having severity here means every other part of the program can just look
# this dictionary up instead of guessing how serious something is.
PATTERNS = {
    "AWS Access Key": {
        # AWS access keys always start with "AKIA" followed by 16 uppercase
        # letters/numbers. That fixed shape makes them very easy to spot.
        "regex": r"AKIA[0-9A-Z]{16}",
        "severity": "High",
    },
    "Generic API Key": {
        # This looks for things like: api_key = "abcdef1234567890..."
        # (?i) means "ignore uppercase/lowercase" so it also matches API_KEY.
        "regex": (
            r"(?i)api[_-]?key['\"']?\s*[:=]\s*['\"'][a-zA-Z0-9_\-]{16,40}['\"']"
        ),
        "severity": "Medium",
    },
    "Insecure Eval": {
        # eval() runs whatever text is inside it as real Python code. If that
        # text ever comes from a user, they could make your program do
        # anything they want. \b means "word boundary" so we match the word
        # "eval" on its own, not part of another word like "myeval".
        "regex": r"\beval\s*\(",
        "severity": "High",
    },
    "Insecure Exec": {
        # exec() is eval()'s cousin - same idea, same danger, slightly
        # different use case (it can run whole blocks of code, not just one
        # expression).
        "regex": r"\bexec\s*\(",
        "severity": "High",
    },
    "Insecure Pickle": {
        # pickle.load() turns saved bytes back into Python objects. The
        # problem: it will happily run code hidden inside a booby-trapped
        # file. Never unpickle data you don't fully trust.
        "regex": r"pickle\.loads?\(",
        "severity": "High",
    },
}

# This just gives each severity word a number, so we can compare them like
# numbers instead of trying to compare text. "High" (3) is worse than
# "Medium" (2) which is worse than "Low" (1). We use this later for the
# --severity filter.
SEVERITY_LEVELS = {"Low": 1, "Medium": 2, "High": 3}

# If we find a hardcoded string being stored in a variable, we only want to
# treat it as a "secret" if the variable's name sounds like it holds one.
# For example: `token = "..."` is suspicious, but `greeting = "..."` is not.
# This tuple lists the keywords we check the variable name against.
SECRET_NAME_HINTS = ("key", "secret", "token", "password", "passwd", "pwd", "credential")

# Dictionary full of common third party github folders that our scanner can safely ignore.
# These are folders full of other people's code (libraries, dependencies,
# compiled output) rather than code you actually wrote, so scanning them
# would just waste time and create noisy, irrelevant findings.
IGNORE_DIRS = {".git", "node_modules", "venv", "__pycache__", "dist", "build"}


def _make_finding(file_path, line_number, vuln_type, snippet, severity, method):
  """Builds one finding dict in our standard shape, whichever detector produced it.

  Think of this as filling out one index card with all the details about a
  single problem we spotted: which file, which line, what kind of problem,
  how serious it is, what the code looked like, and how we found it. Both of
  our scanning engines (regex and AST, explained further down) call this
  function so that every finding - no matter which engine caught it - ends
  up looking exactly the same in the final report.
  """
  return {
      "file_path": file_path,
      "line_number": line_number,
      "vulnerability_type": vuln_type,
      "severity": severity,
      "matched_snippet": snippet.strip(),
      "detection_method": method,  # "ast" or "regex", so you can see which engine caught it
  }


def scan_file_regex(file_path):
  """Line-by-line regex scan. This is our original, universal fallback: it works on
  any text file (Python, JS, config files, .env files, etc.) but can't tell the
  difference between real code and a comment or string that merely looks dangerous.

  How it works, step by step:
    1. Open the file as plain text.
    2. Go through it one line at a time, keeping count of the line number.
    3. For each line, check it against every pattern in PATTERNS.
    4. Any time a pattern matches, record a finding.
  """
  findings = []
  try:
    # encoding="utf-8" tells Python how to interpret the bytes as text.
    # errors="ignore" means: if a file has some weird/broken characters in
    # it (common in binary files we accidentally open), just skip those
    # characters instead of crashing the whole scan.
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
      # enumerate(f, 1) walks through the file line by line, and also hands
      # us a line number starting at 1 (instead of starting at 0).
      for line_num, line in enumerate(f, 1):
        for vuln_type, meta in PATTERNS.items():
          # re.search looks for the pattern ANYWHERE in the line (it doesn't
          # need to match the whole line, just find the pattern somewhere
          # inside it).
          if re.search(meta["regex"], line):
            findings.append(
                _make_finding(
                    file_path, line_num, vuln_type, line, meta["severity"], "regex"
                )
            )
  except Exception as e:
    # If a file can't be opened for some reason (permissions, it's actually
    # a weird binary file, etc.), don't crash the whole scan - just print a
    # warning and move on to the next file.
    print(f"Could not read {file_path}: {e}")
  return findings


def _looks_like_secret_name(name):
  """Checks a variable/attribute name against common secret-y keywords.

  Example: _looks_like_secret_name("api_token") -> True (contains "token")
           _looks_like_secret_name("username")  -> False
  """
  if not name:
    return False
  lower = name.lower()  # normalize to lowercase so "TOKEN" also matches "token"
  return any(hint in lower for hint in SECRET_NAME_HINTS)


def _target_names(target):
  """Pulls variable/attribute names out of an assignment target, including
  tuple/list unpacking like `a, b = ...`.

  This is a small helper for the AST engine below. When Python parses code
  like `api_key = "abc123"`, the "target" (the left-hand side of the `=`) is
  represented as a small tree of its own, not just a plain string. This
  function digs into that tree and pulls out the plain name(s) so the rest
  of our code can work with simple strings like "api_key" instead of having
  to understand Python's internal tree structure itself.
  """
  names = []
  if isinstance(target, ast.Name):
    # The simple case: `api_key = ...` -> target.id is "api_key"
    names.append(target.id)
  elif isinstance(target, ast.Attribute):
    # The "attribute" case: `self.api_key = ...` -> target.attr is "api_key"
    names.append(target.attr)
  elif isinstance(target, (ast.Tuple, ast.List)):
    # The "unpacking" case: `user, token = ...` - there's more than one
    # target here, so we recurse (call this same function again) on each
    # piece to collect every name involved.
    for elt in target.elts:
      names.extend(_target_names(elt))
  return names


def _call_name(node):
  """Returns a readable name for a Call node's function, e.g. 'eval' or 'pickle.load'.

  When the AST sees code like `eval(x)`, it represents "eval" as its own
  little tree too. This helper turns that tree back into a plain, readable
  string so we can compare it with simple `==` checks later on, instead of
  writing out the tree-walking logic every single time we need a name.
  """
  func = node.func
  if isinstance(func, ast.Name):
    # A plain function call, like eval(...) or exec(...).
    return func.id
  if isinstance(func, ast.Attribute):
    # A "dotted" call, like pickle.load(...). func.value is the "pickle"
    # part and func.attr is the "load" part.
    if isinstance(func.value, ast.Name):
      return f"{func.value.id}.{func.attr}"
    return func.attr
  return None


def scan_file_ast(file_path):
  """AST-based scan for Python source. This understands actual code structure, so it
  won't flag 'eval(' sitting inside a comment or docstring, and it only calls something
  a hardcoded secret when it's a real assignment to a suspiciously-named variable.
  Returns None (rather than []) when the file can't be parsed, so the caller knows to
  fall back to the regex scanner instead of silently reporting zero findings.

  BEGINNER NOTE ON "AST": AST stands for Abstract Syntax Tree. It's the same
  structure Python itself builds internally when it reads your code, before
  running it. Instead of treating a Python file as one long block of text
  (like the regex scanner does), the `ast` module turns it into a tree of
  meaningful pieces: "this is a function call", "this is an assignment",
  "this is a string", and so on. That lets us ask precise questions like
  "is `eval` actually being called here?" instead of "does the text 'eval('
  show up somewhere on this line?" - which is what makes this engine so much
  more accurate than plain regex for Python files.
  """
  findings = []
  try:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
      source = f.read()
    # ast.parse() is where the magic happens: it reads the whole source
    # file and builds that tree structure mentioned above. If the file
    # isn't valid Python (a syntax error, or it's actually Python 2 code,
    # etc.), this line will raise an exception.
    tree = ast.parse(source, filename=file_path)
  except (SyntaxError, ValueError, UnicodeDecodeError):
    # We couldn't parse it as Python, so tell the caller "no AST result" by
    # returning None. scan_file() (further down) knows to fall back to the
    # regex scanner when it sees None.
    return None
  except Exception as e:
    print(f"Could not parse {file_path}: {e}")
    return None

  # Split the original source into a list of lines so that, once we find a
  # problem on a particular line number, we can pull the actual line of
  # code back out to show the user what was matched.
  source_lines = source.splitlines()

  def line_snippet(lineno):
    """Safely grabs the text of a given line number (1-indexed) from the file."""
    if 1 <= lineno <= len(source_lines):
      return source_lines[lineno - 1]  # -1 because lists start counting at 0
    return ""

  # ast.walk(tree) visits every single node (piece) in the syntax tree, one
  # at a time, in no particular guaranteed order. This is like walking
  # through every room of a house to check each one, rather than only
  # looking at the front door.
  for node in ast.walk(tree):
    # --- Dangerous function calls ---
    # isinstance(node, ast.Call) asks: "is this tree node a function call?"
    # (as opposed to, say, a variable, a loop, or an if-statement).
    if isinstance(node, ast.Call):
      name = _call_name(node)
      if name == "eval":
        meta = PATTERNS["Insecure Eval"]
        findings.append(
            _make_finding(
                file_path, node.lineno, "Insecure Eval",
                line_snippet(node.lineno), meta["severity"], "ast",
            )
        )
      elif name == "exec":
        meta = PATTERNS["Insecure Exec"]
        findings.append(
            _make_finding(
                file_path, node.lineno, "Insecure Exec",
                line_snippet(node.lineno), meta["severity"], "ast",
            )
        )
      elif name in ("pickle.load", "pickle.loads"):
        meta = PATTERNS["Insecure Pickle"]
        findings.append(
            _make_finding(
                file_path, node.lineno, "Insecure Pickle",
                line_snippet(node.lineno), meta["severity"], "ast",
            )
        )

    # --- Hardcoded secret assignments ---
    # isinstance(node, ast.Assign) asks: "is this tree node an assignment
    # statement?" (anything of the shape `something = something_else`).
    if isinstance(node, ast.Assign):
      value = node.value
      # ast.Constant covers literal values written directly in the code,
      # like "abc123", 42, or True. We only care about string constants
      # here, since that's what a hardcoded secret would look like.
      if isinstance(value, ast.Constant) and isinstance(value.value, str):
        str_val = value.value
        names = []
        # node.targets is a list because Python allows chained assignment
        # like `a = b = "value"` - we check every target being assigned to.
        for target in node.targets:
          names.extend(_target_names(target))

        # First check: does the string itself look like an AWS key,
        # regardless of what the variable is called? AWS keys have a very
        # distinct, recognizable shape, so this check doesn't need the
        # variable name's help.
        if re.search(PATTERNS["AWS Access Key"]["regex"], str_val):
          meta = PATTERNS["AWS Access Key"]
          findings.append(
              _make_finding(
                  file_path, node.lineno, "AWS Access Key",
                  line_snippet(node.lineno), meta["severity"], "ast",
              )
          )
        # Second check: does the variable's name sound like a secret
        # (using _looks_like_secret_name), AND is the string long enough
        # to plausibly be a real credential rather than a short label or
        # placeholder? Both conditions need to be true (that's what `and`
        # means) before we flag it.
        elif any(_looks_like_secret_name(n) for n in names) and len(str_val) >= 16:
          meta = PATTERNS["Generic API Key"]
          findings.append(
              _make_finding(
                  file_path, node.lineno, "Generic API Key",
                  line_snippet(node.lineno), meta["severity"], "ast",
              )
          )

  return findings


def scan_file(file_path):
  """Picks the right detector for the file. Python files get the more precise
  AST-based scan; everything else (and any Python file that fails to parse,
  e.g. Python 2 syntax) falls back to the regex scan.

  This function is the "traffic cop" of the whole program: every single file
  we scan passes through here first, and this is what decides which of our
  two engines actually looks at it.
  """
  if file_path.endswith(".py"):
    ast_findings = scan_file_ast(file_path)
    # Remember: scan_file_ast() returns None (not an empty list) when it
    # couldn't parse the file at all. `is not None` makes sure we only skip
    # the regex fallback when the AST scan genuinely succeeded - even if it
    # found zero findings.
    if ast_findings is not None:
      return ast_findings
  return scan_file_regex(file_path)


def scan_codebase(target):
  """Walks a directory (or scans a single file directly) and collects findings
  from every file, skipping the noisy directories in IGNORE_DIRS.

  "target" can be either:
    - a path to a single file, e.g. "vulnerable_sample.py", or
    - a path to a folder, e.g. "." (the current directory) or "/my/project"
  """
  if os.path.isfile(target):
    # The user pointed us at one specific file rather than a whole folder,
    # so there's nothing to "walk" - just scan that one file directly.
    return scan_file(target)

  all_findings = []
  # os.walk() is a handy built-in that visits every folder inside "target",
  # one at a time. For each folder it visits, it hands us:
  #   root  -> the current folder's path
  #   dirs  -> the list of sub-folders inside it (that we're ABOUT to visit)
  #   files -> the list of files inside it
  for root, dirs, files in os.walk(target):
    # This line modifies `dirs` in place to remove any folder names that
    # appear in IGNORE_DIRS. Because os.walk() checks `dirs` before
    # descending into each one, this effectively tells it "don't even
    # bother looking inside .git, node_modules, venv, etc."
    dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
    for file in files:
      # os.path.join builds a proper file path for the current operating
      # system (using "/" on Mac/Linux, "\" on Windows) instead of us
      # having to glue strings together by hand.
      file_path = os.path.join(root, file)
      all_findings.extend(scan_file(file_path))
  return all_findings


# The main function brings everything together, filters by severity, and saves
# the results as a JSON report.
def main():
  # argparse builds a friendly command-line interface for us: it reads
  # whatever the user typed after "python SAST_Scanner.py ...", checks it
  # against the rules below, and even auto-generates a --help message.
  parser = argparse.ArgumentParser(description="Simple Code Security Scanner")

  # A "positional" argument - the user must supply it, and it doesn't need a
  # flag in front of it. Example: `python SAST_Scanner.py my_project/`
  parser.add_argument("target", help="Path to the directory or file you want to scan")

  # An "optional" argument with a flag. If the user doesn't provide -o, it
  # quietly falls back to the default filename shown here.
  parser.add_argument(
      "-o", "--output", default="scan_results.json", help="Output JSON file name"
  )

  # Another optional flag. `choices=[...]` means argparse will automatically
  # reject (with a helpful error message) anything that isn't exactly one of
  # these three words, so we don't have to check that ourselves later.
  parser.add_argument(
      "--severity",
      choices=["Low", "Medium", "High"],
      default="Low",
      help=(
          "Minimum severity to include in the report. 'High' shows only High "
          "findings; 'Low' (the default) shows everything."
      ),
  )

  # This actually reads sys.argv (what the user typed) and turns it into a
  # simple object where args.target, args.output, and args.severity hold
  # whatever values were provided (or their defaults).
  args = parser.parse_args()

  # Do the actual scanning work - this is everything we've built above,
  # kicked off with one function call.
  findings = scan_codebase(args.target)

  # Turn the chosen severity word ("Low"/"Medium"/"High") into its matching
  # number using SEVERITY_LEVELS, then keep only the findings whose severity
  # number is equal to or greater than that. This is a "list comprehension":
  # a compact way of writing "build a new list by keeping only the items
  # from `findings` that pass this condition".
  min_level = SEVERITY_LEVELS[args.severity]
  filtered_findings = [
      f for f in findings if SEVERITY_LEVELS[f["severity"]] >= min_level
  ]

  # Build one tidy dictionary holding the whole report, ready to be saved as
  # JSON (JSON is just a standard, widely-understood text format for
  # structured data like this).
  report = {
      "scan_timestamp": datetime.utcnow().isoformat() + "Z",
      "severity_filter": args.severity,
      "total_findings": len(filtered_findings),
      "vulnerabilities": filtered_findings,
  }

  # Write the report out to disk. indent=4 makes the JSON file nicely
  # readable by humans (with line breaks and indentation) instead of being
  # one giant unreadable line of text.
  with open(args.output, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4)

  print(
      f"Scan complete! {len(filtered_findings)} finding(s) at or above "
      f"'{args.severity}' severity. Results saved to {args.output}"
  )


# This is a common Python pattern: it means "only run main() if this file
# was executed directly (like `python SAST_Scanner.py ...`), not if it was
# imported by some other Python file as a helper module."
if __name__ == "__main__":
  main()
