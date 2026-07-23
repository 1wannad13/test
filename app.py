"""
Simple Flask search application.

Demonstrates OWASP Top Ten Proactive Controls (2024) - C3: Validate All
Input, plus related references:
  - OWASP ASVS 5.1 (Input Validation Requirements)
  - OWASP Cheat Sheet Series: Input Validation Cheat Sheet
  - OWASP Cheat Sheet Series: SQL Injection Prevention Cheat Sheet
  - OWASP Cheat Sheet Series: Cross Site Scripting Prevention Cheat Sheet

Pages:
  GET  /            Home / search page: form with one input + submit button.
  POST /search       Validates the search term server-side. If invalid,
                      the user is bounced back to the home page (empty
                      input, error message). If valid, the term is stored
                      and the user is sent to the result page.
  GET  /result/<id>  Displays the stored (validated, escaped) search term
                      and a "Back" button.

Validation strategy (defense in depth):
  1. Positive / allow-list validation - only a known-safe character set
     is accepted (letters, digits, spaces, and a small set of punctuation).
     Everything else is rejected outright. This is the primary control
     recommended by C3 and the OWASP Input Validation Cheat Sheet.
  2. Length validation - minimum and maximum length enforced.
  3. Deny-list pattern check - a secondary, explicit check for common
     SQL injection and XSS payload signatures (e.g. UNION SELECT,
     <script>, javascript:, onerror=). Belt-and-braces on top of #1,
     and gives a clearer signal that an attack was attempted.
  4. Parameterized SQL - the query text is NEVER concatenated into SQL.
     psycopg2 parameter binding (%s placeholders) is used for every
     statement, which prevents SQL injection regardless of what content
     passes validation.
  5. Output encoding - Jinja2 autoescaping is left on (Flask default),
     so any value rendered into HTML is escaped, preventing stored/
     reflected XSS.
"""
import os
import re
from datetime import datetime

import psycopg2
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, abort
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-not-for-prod")

# ---------------------------------------------------------------------------
# Database configuration (read from environment - see docker-compose.yml)
# ---------------------------------------------------------------------------
DB_HOST = os.environ.get("DB_HOST", "db")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "searchdb")
DB_USER = os.environ.get("DB_USER", "appuser")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "apppassword")

# Table name is a literal requirement: "2402554". It starts with a digit,
# so it must be double-quoted as an identifier in every SQL statement.
TABLE_NAME = '"2402554"'


def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASSWORD,
    )


# ---------------------------------------------------------------------------
# OWASP C3 - Input validation (server side / backend)
# ---------------------------------------------------------------------------
MIN_LEN = 2
MAX_LEN = 50

# Allow-list: letters, digits, spaces, and a small set of safe punctuation.
# Anything outside this set (<, >, ', ", ;, =, /, \, %, `, (, ), {, }, etc.)
# is rejected. This alone blocks the overwhelming majority of SQLi/XSS
# payloads because the characters they depend on simply aren't permitted.
ALLOWED_PATTERN = re.compile(r"^[A-Za-z0-9 .,_\-?!]+$")

# Deny-list: explicit, defense-in-depth check for well-known SQL
# injection / XSS attack signatures. Case-insensitive.
ATTACK_PATTERNS = [
    r"--",
    r";",
    r"/\*|\*/",
    r"<\s*script",
    r"<\s*/\s*script",
    r"<\s*iframe",
    r"<\s*img",
    r"javascript\s*:",
    r"on\w+\s*=",  # onerror=, onload=, onclick=, ...
    r"\bunion\b\s+\bselect\b",
    r"\bselect\b.+\bfrom\b",
    r"\binsert\b\s+\binto\b",
    r"\bupdate\b.+\bset\b",
    r"\bdelete\b\s+\bfrom\b",
    r"\bdrop\b\s+\btable\b",
    r"\bexec\b\s*\(",
    r"\balert\b\s*\(",
    r"'\s*or\s*'?\d*'?\s*=\s*'?\d*",  # ' or '1'='1
]
ATTACK_REGEXES = [re.compile(p, re.IGNORECASE) for p in ATTACK_PATTERNS]


def validate_search_term(raw_term: str):
    """
    Validate a raw search term per OWASP C3.

    Returns (True, cleaned_term) if valid.
    Returns (False, reason) if invalid - caller must discard the input.
    """
    term = (raw_term or "").strip()

    if len(term) == 0:
        return False, "Search term is required."

    if len(term) < MIN_LEN or len(term) > MAX_LEN:
        return False, f"Search term must be between {MIN_LEN} and {MAX_LEN} characters."

    if not ALLOWED_PATTERN.match(term):
        return False, (
            "Search term contains characters that are not allowed. "
            "Only letters, numbers, spaces, and . , - _ ? ! are permitted."
        )

    for pattern in ATTACK_REGEXES:
        if pattern.search(term):
            return False, "Search term rejected: input looks like an attack payload."

    return True, term


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    """Home / search page: renders the form. Input is always empty here,
    which is what guarantees the field is cleared after a rejected
    submission (we redirect back to this GET route rather than
    re-rendering the posted value)."""
    return render_template("index.html")


@app.route("/search", methods=["POST"])
def search():
    raw_term = request.form.get("search_term", "")
    valid, result = validate_search_term(raw_term)

    if not valid:
        # Invalid / attack-like input: do NOT store it, do NOT reflect it
        # back into the page. Flash a generic error and return to the
        # home page with a blank input field.
        flash(result, "error")
        return redirect(url_for("index"))

    cleaned_term = result

    # Store the validated query using a parameterized statement, and log
    # the query time (DB default CURRENT_TIMESTAMP, returned via RETURNING).
    conn = get_db_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    f'INSERT INTO {TABLE_NAME} (query_text, query_time) '
                    f'VALUES (%s, %s) RETURNING id;',
                    (cleaned_term, datetime.utcnow()),
                )
                new_id = cur.fetchone()[0]
    finally:
        conn.close()

    return redirect(url_for("result", query_id=new_id))


@app.route("/result/<int:query_id>", methods=["GET"])
def result(query_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f'SELECT query_text, query_time FROM {TABLE_NAME} WHERE id = %s;',
                (query_id,),
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if row is None:
        abort(404)

    query_text, query_time = row
    # query_text is passed to Jinja2, which auto-escapes it on render -
    # this is the output-encoding half of XSS prevention.
    return render_template("result.html", query_text=query_text, query_time=query_time)


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
