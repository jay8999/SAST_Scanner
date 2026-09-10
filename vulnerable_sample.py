# Intentionally vulnerable code snippet for testing SAST_Scanner.py.
# Nothing in this file should ever be copied into a real project - every
# line here exists purely so we have a known, guaranteed-to-be-flagged
# target to run the scanner against and confirm it's actually working.

# --- Problem 1: Hardcoded AWS Access Key ---
# Real AWS credentials should live in environment variables, a secrets
# manager, or a config file that's excluded from version control (e.g. via
# .gitignore) - never typed directly into source code like this. If this
# file were pushed to a public GitHub repo, anyone could copy this key and
# use it to rack up charges (or worse) on the account it belongs to.
# (This particular key is AWS's own well-known public example key, safe to
# use for testing - but the scanner doesn't know that, which is the point!)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# --- Problem 2: Hardcoded Generic API Key ---
# Same idea as above, but for a generic-looking API key/token instead of an
# AWS-specific one. Any secret baked directly into source code is a risk:
# it ends up in your git history forever, even if you delete it later.
api_key = "api_key = '1234567890abcdef1234567890abcdef'"


# --- Problem 3: Insecure use of eval() ---
# eval() takes a string and runs it as if it were real Python code. Here,
# `user_data` could be anything an outside user typed in - which means they
# could make this function run ANY Python code they want on your machine
# (read files, delete files, steal other secrets, etc.). This is one of the
# most dangerous patterns a scanner can catch.
def bad_code(user_data):
  eval(user_data)
