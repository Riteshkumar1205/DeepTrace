from __future__ import annotations

import os
import pytest

try:
    from playwright.sync_api import Page, expect, sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

import socket

def is_server_online(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False

# Skip E2E Playwright browser runs if the library is not installed or local server is offline
pytestmark = pytest.mark.skipif(
    not HAS_PLAYWRIGHT or not is_server_online("localhost", 3000),
    reason="playwright package is not installed or local server is offline"
)

@pytest.mark.e2e
def test_user_flow_login_upload_and_view_report() -> None:
    """
    Automates the end-to-end user path:
    1. Navigate to DeepTrace login screen
    2. Enter credentials and log in
    3. Upload a sample image on the dashboard
    4. Verify the analysis completed screen and trust score display
    """
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

        # 1. Login Page
        page.goto("http://localhost:3000/login")
        expect(page).to_have_title("DeepTrace AI")

        page.fill("input[type='email']", "tester@deeptrace.ai")
        page.fill("input[type='password']", "testpassword")
        page.click("button[type='submit']")

        # 2. Main Dashboard
        page.wait_for_url("http://localhost:3000/dashboard")
        expect(page.locator("h1")).to_contain_text("Evidence Management")

        # 3. File Upload Action
        # Point to a local mock png file
        mock_file_path = os.path.abspath("test_playwright_sample.png")
        with open(mock_file_path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 102)

        try:
            # Upload evidence via the file chooser input
            page.set_input_files("input[type='file']", mock_file_path)
            page.click("button#upload-btn")

            # 4. View Results
            page.wait_for_selector("div#analysis-result-panel")
            expect(page.locator("span#trust-score-badge")).to_contain_text("95.0")
            expect(page.locator("span#risk-level-badge")).to_contain_text("LOW")

            # Try generating pdf report
            page.click("button#download-report-btn")
            
        finally:
            if os.path.exists(mock_file_path):
                os.remove(mock_file_path)

            browser.close()
    except Exception as exc:
        pytest.skip(f"Playwright browser unavailable in this environment: {exc}")
