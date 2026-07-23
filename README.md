# Search Web App

Simple Flask + PostgreSQL search app demonstrating OWASP Top Ten Proactive
Controls (2024) **C3: Validate All Input**.

## Run it

```bash
cd webapp
docker compose up --build
```

Then open http://localhost:8080

To stop: `docker compose down` (add `-v` to also delete the database volume).

## Pages

- `GET /` — home / search page: one input field + submit button.
- `POST /search` — validates the term server-side. Invalid input (fails
  length checks, allow-list, or looks like a SQLi/XSS payload) is
  discarded; you're sent back to `/` with the field empty and an error
  message. Valid input is stored and you're redirected to the result page.
- `GET /result/<id>` — shows the stored search term and query time, with
  a **Back** button to `/`.

## How OWASP C3 (Validate All Input) is applied

Validation happens in **two places**, both implementing the same rules —
the frontend for UX, the backend as the actual trust boundary (frontend
checks can always be bypassed):

- `webapp/static/js/validate.js` — client-side validation.
- `webapp/app.py` (`validate_search_term`) — server-side validation.

Each performs, in order:

1. **Length check** — term must be 2–50 characters.
2. **Positive (allow-list) validation** — only letters, digits, spaces,
   and `. , - _ ? !` are accepted. Everything else (`<`, `>`, `'`, `"`,
   `;`, `=`, `/`, backticks, parentheses, etc.) is rejected outright.
   This is the primary control recommended by the OWASP Input
   Validation Cheat Sheet and blocks nearly all SQLi/XSS payload syntax
   by construction.
3. **Deny-list check** — a secondary, explicit scan for known SQL
   injection and XSS signatures (`UNION SELECT`, `<script>`,
   `javascript:`, `onerror=`, `' OR '1'='1`, `--`, `;`, etc.), for
   defense in depth and a clearer rejection reason.

On the backend, two further controls complete the picture (per the OWASP
SQL Injection Prevention and XSS Prevention Cheat Sheets):

- **Parameterized SQL** — every query uses `%s` placeholders via
  psycopg2; the search term is never concatenated into SQL text.
- **Output encoding** — the result page renders the stored term through
  Jinja2's default autoescaping, so it can never execute as HTML/JS when
  displayed back.

References: OWASP Top Ten Proactive Controls 2024 (C3), OWASP ASVS 5.1,
OWASP Input Validation Cheat Sheet, OWASP SQL Injection Prevention Cheat
Sheet, OWASP XSS Prevention Cheat Sheet.

## Architecture

- `web` container — Python 3.12 slim + gunicorn, serves the Flask app
  directly on port 8080. No nginx container is used; `web` plays that
  role itself (per the "can use other web app container to replace
  nginx" requirement).
- `db` container — `postgres:16-alpine`. `db/init.sql` is auto-run on
  first start and creates table `"2402554"` (double-quoted because the
  name starts with a digit) with columns `id`, `query_text`,
  `query_time`.

## Files

```
webapp/
├── app.py                 # Flask app: routes + validation + DB access
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── db/
│   └── init.sql            # creates table "2402554"
├── templates/
│   ├── index.html           # home / search page
│   ├── result.html          # result page
│   └── 404.html
└── static/
    ├── css/style.css
    └── js/validate.js       # client-side validation
```

## Notes

- Credentials in `docker-compose.yml` are for local/demo use only — swap
  them for secrets/env files before any real deployment.
- `FLASK_SECRET_KEY` is used for flash-message signing (session cookie);
  set a real random value via environment for production use.
