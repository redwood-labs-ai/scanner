# FP baseline: Python patterns that should not trigger findings.

import os

# Dev credentials - environment variable assignments
POSTGRES_PASSWORD = "localdev"
DB_PASSWORD = "test1234"
SECRET_KEY = "changeme"
REDIS_PASSWORD = "docker"

# Password field names that are NOT credential values
password_confirm = request.form.get("password_confirm")
password_hash = hash_password(raw_password)
password_field = form.fields["password"]

# Template literals / f-strings with innocent content
status_msg = f"Greeting: {new_status}"
chosen_msg = f"Chosen option: {option}"
