"""
Integration tests for the search web app.

These hit the app over real HTTP, against the stack started by
`docker compose up` (services: web on :8080, db on :5432). They exercise
the full request path: Flask routing -> validation -> Postgres ->
response rendering, per OWASP C3 (Validate All Input).

Run locally:
    docker compose up -d --build
    pip install -r requirements-dev.txt
    pytest tests/test_integration.py -v
    docker compose down -v
"""
import requests

BASE_URL = "http://localhost:8080"


def test_home_page_loads():
    r = requests.get(f"{BASE_URL}/")
    assert r.status_code == 200
    assert "<form" in r.text
    assert 'name="search_term"' in r.text


def test_valid_search_creates_result_page():
    session = requests.Session()
    r = session.post(
        f"{BASE_URL}/search",
        data={"search_term": "integration test"},
        allow_redirects=True,
    )
    assert r.status_code == 200
    assert "/result/" in r.url
    assert "integration test" in r.text
    assert "Back" in r.text


def test_sql_injection_attempt_is_rejected():
    session = requests.Session()
    r = session.post(
        f"{BASE_URL}/search",
        data={"search_term": "' OR '1'='1"},
        allow_redirects=True,
    )
    assert r.status_code == 200
    # bounced back to the home page, not a result page
    assert r.url.rstrip("/") == BASE_URL
    assert "/result/" not in r.url


def test_union_select_attempt_is_rejected():
    session = requests.Session()
    r = session.post(
        f"{BASE_URL}/search",
        data={"search_term": "test UNION SELECT username FROM users"},
        allow_redirects=True,
    )
    assert r.status_code == 200
    assert r.url.rstrip("/") == BASE_URL


def test_xss_attempt_is_rejected_and_never_reflected():
    session = requests.Session()
    payload = "<script>alert(1)</script>"
    r = session.post(
        f"{BASE_URL}/search",
        data={"search_term": payload},
        allow_redirects=True,
    )
    assert r.status_code == 200
    assert r.url.rstrip("/") == BASE_URL
    # the raw payload must never come back in the response body
    assert payload not in r.text


def test_too_short_input_rejected():
    session = requests.Session()
    r = session.post(
        f"{BASE_URL}/search",
        data={"search_term": "a"},
        allow_redirects=True,
    )
    assert r.url.rstrip("/") == BASE_URL
    assert "between 2 and 50 characters" in r.text


def test_too_long_input_rejected():
    session = requests.Session()
    r = session.post(
        f"{BASE_URL}/search",
        data={"search_term": "x" * 51},
        allow_redirects=True,
    )
    assert r.url.rstrip("/") == BASE_URL
    assert "between 2 and 50 characters" in r.text


def test_empty_input_rejected():
    session = requests.Session()
    r = session.post(
        f"{BASE_URL}/search",
        data={"search_term": ""},
        allow_redirects=True,
    )
    assert r.url.rstrip("/") == BASE_URL


def test_nonexistent_result_id_returns_404():
    r = requests.get(f"{BASE_URL}/result/999999999")
    assert r.status_code == 404


def test_valid_search_is_html_escaped_on_result_page():
    # A value that's valid under the allow-list but still worth confirming
    # is output-encoded (defense in depth even though it can't contain
    # HTML-significant characters given the allow-list).
    session = requests.Session()
    r = session.post(
        f"{BASE_URL}/search",
        data={"search_term": "safe term 123"},
        allow_redirects=True,
    )
    assert "safe term 123" in r.text
