from __future__ import annotations

import socket
import time

import httpx
import pytest

try:
    from playwright.sync_api import expect, sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


def is_server_online(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not HAS_PLAYWRIGHT or not is_server_online("localhost", 3000) or not is_server_online("localhost", 8000),
    reason="playwright package is not installed or local services are offline",
)


@pytest.mark.e2e
def test_auth_pages_and_dashboard_flow() -> None:
    email = f"playwright.{int(time.time())}@example.com"
    password = "Playwright123!"

    with httpx.Client(timeout=20.0) as client:
        register = client.post(
            "http://localhost:8000/api/v1/auth/register",
            json={
                "email": email,
                "password": password,
                "full_name": "Playwright Tester",
                "organization_name": "DeepTrace QA",
            },
        )
        register.raise_for_status()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()

        page.goto("http://localhost:3000/login")
        page.wait_for_selector("input[type='email']")
        expect(page.get_by_role("heading", name="Sign in")).to_be_visible()

        page.goto("http://localhost:3000/register")
        page.wait_for_selector("input[type='email']")
        expect(page.get_by_role("heading", name="Create account")).to_be_visible()

        page.goto("http://localhost:3000/forgot-password")
        page.wait_for_selector("input[type='email']")
        expect(page.get_by_role("heading", name="Reset access")).to_be_visible()

        page.goto("http://localhost:3000/reset-password")
        page.wait_for_selector("input[type='email']")
        expect(page.get_by_role("heading", name="Set new password")).to_be_visible()

        page.goto("http://localhost:3000/login")
        page.wait_for_selector("input[type='email']")
        page.get_by_label("Email").fill(email)
        page.locator("input[type='password']").first.fill(password)
        page.get_by_role("button", name="Sign in").click()

        page.wait_for_url("http://localhost:3000/", wait_until="commit")
        expect(page.locator("body")).to_contain_text("DeepTrace SOC")

        browser.close()
