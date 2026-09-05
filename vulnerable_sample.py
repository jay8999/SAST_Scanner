# Intentionally vulnerable code snippet for testing scanner.py
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
api_key = "api_key = '1234567890abcdef1234567890abcdef'"


def bad_code(user_data):
  eval(user_data)