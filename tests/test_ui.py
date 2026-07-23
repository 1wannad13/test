"""
UI tests for the search web app, driven over HTTP with a real headless
browser (Playwright), against the stack started by `docker compose up`.

These cover both the happy path (submit -> result page -> back button)
and the client-side validation layer in static/js/validate.js.

Run locally:
    docker compose up -d --build
    pip install -r requirements-dev.txt
    playwright install --with-deps chromium
    pytest tests/test_ui.py -v
    docker compose down -v
"""
import re

from playwright.sync_api import Page, expect

BASE_URL = "http://localhost:8080"


def test_home_page_has_search_form(page: Page):
    page.goto(f"{BASE_URL}/")
    expect(page.locator("#search_term")).to_be_visible()
    expect(page.locator("button[type=submit]")).to_be_visible()


def test_valid_search_navigates_to_result_page(page: Page):
    page.goto(f"{BASE_URL}/")
    page.fill("#search_term", "playwright ui test")
    page.click("button[type=submit]")

    page.wait_for_url(re.compile(r".*/result/\d+"))
    expect(page.locator(".result-value")).to_have_text("playwright ui test")
    expect(page.locator(".back-btn")).to_be_visible()


def test_back_button_returns_to_empty_home_page(page: Page):
    page.goto(f"{BASE_URL}/")
    page.fill("#search_term", "back button check")
    page.click("button[type=submit]")
    page.wait_for_url(re.compile(r".*/result/\d+"))

    page.click(".back-btn")
    page.wait_for_url(f"{BASE_URL}/")
    expect(page.locator("#search_term")).to_have_value("")


def test_xss_payload_blocked_client_side(page: Page):
    page.goto(f"{BASE_URL}/")
    page.fill("#search_term", "<script>alert(1)</script>")
    page.click("button[type=submit]")

    # Client-side validation should intercept the submit - we never
    # leave the home page.
    expect(page).to_have_url(f"{BASE_URL}/")
    expect(page.locator("#client-error")).to_be_visible()
    expect(page.locator("#search_term")).to_have_value("")


def test_sql_injection_payload_blocked_client_side(page: Page):
    page.goto(f"{BASE_URL}/")
    page.fill("#search_term", "' OR '1'='1")
    page.click("button[type=submit]")

    expect(page).to_have_url(f"{BASE_URL}/")
    expect(page.locator("#client-error")).to_be_visible()
    expect(page.locator("#search_term")).to_have_value("")


def test_too_short_input_blocked_client_side(page: Page):
    page.goto(f"{BASE_URL}/")
    page.fill("#search_term", "a")
    page.click("button[type=submit]")

    expect(page).to_have_url(f"{BASE_URL}/")
    expect(page.locator("#client-error")).to_be_visible()


def test_error_message_clears_when_user_retypes(page: Page):
    page.goto(f"{BASE_URL}/")
    page.fill("#search_term", "a")
    page.click("button[type=submit]")
    expect(page.locator("#client-error")).to_be_visible()

    page.fill("#search_term", "now a valid term")
    expect(page.locator("#client-error")).to_be_hidden()
