from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

@pytest.mark.security
def test_owasp_zap_security_headers_compliance(client: TestClient) -> None:
    """
    Audits the API response security headers to protect against
    common web vulnerabilities (Clickjacking, MIME sniffing, XSS, CSRF).
    """
    response = client.get("/api/v1/auth/login")
    # Even if login fails/unauthorized or returns 400, headers should be set securely.
    
    headers = response.headers

    # 1. Anti-Clickjacking: X-Frame-Options
    assert "x-frame-options" in headers or "X-Frame-Options" in headers
    frame_opt = headers.get("x-frame-options") or headers.get("X-Frame-Options")
    assert frame_opt in ["DENY", "SAMEORIGIN"]

    # 2. Anti-MIME Sniffing: X-Content-Type-Options
    assert "x-content-type-options" in headers or "X-Content-Type-Options" in headers
    content_type_opt = headers.get("x-content-type-options") or headers.get("X-Content-Type-Options")
    assert content_type_opt == "nosniff"

    # 3. Cross-Site Scripting protection: X-XSS-Protection
    # Note: Modern browsers use CSP, but standard security checklists still check XSS protection.
    if "x-xss-protection" in headers or "X-XSS-Protection" in headers:
        xss_opt = headers.get("x-xss-protection") or headers.get("X-XSS-Protection")
        assert "1; mode=block" in xss_opt


@pytest.mark.security
def test_owasp_zap_cors_policy_check(client: TestClient) -> None:
    """
    Scans for wildcards or overly permissive Access-Control-Allow-Origin headers.
    """
    response = client.options("/api/v1/auth/login", headers={
        "Origin": "http://evil-attacker.com",
        "Access-Control-Request-Method": "POST"
    })
    
    # Permission should be denied or origin should not reflect the wildcards/permissive inputs
    origin = response.headers.get("access-control-allow-origin") or response.headers.get("Access-Control-Allow-Origin")
    if origin:
        assert origin != "*"
        assert origin != "http://evil-attacker.com"
