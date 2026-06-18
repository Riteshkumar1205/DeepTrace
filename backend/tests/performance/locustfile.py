import os
import random
from locust import HttpUser, task, between

class DeepTraceLoadTestUser(HttpUser):
    # Think time between tasks: 1-3 seconds
    wait_time = between(1.0, 3.0)

    def on_start(self):
        """Executed when a virtual user starts: registers/logins and seeds context."""
        self.auth_token = None
        self.case_id = 1  # Standard test case seeded in test/dev db
        
        # Attempt to login using seed credentials
        payload = {"email": "tester@deeptrace.ai", "password": "testpassword"}
        response = self.client.post("/api/v1/auth/login", json=payload)
        
        if response.status_code == 200:
            self.auth_token = response.json().get("access_token")
            self.headers = {"Authorization": f"Bearer {self.auth_token}"}
        else:
            # Fallback if DB is not seeded: register first
            register_payload = {
                "email": f"load_user_{random.randint(1000, 9999)}@deeptrace.ai",
                "password": "strong-password-123",
                "full_name": "Load Test Bot",
                "organization_name": "Load Testing Org"
            }
            self.client.post("/api/v1/auth/register", json=register_payload)
            login_resp = self.client.post("/api/v1/auth/login", json={
                "email": register_payload["email"], "password": register_payload["password"]
            })
            if login_resp.status_code == 200:
                self.auth_token = login_resp.json().get("access_token")
                self.headers = {"Authorization": f"Bearer {self.auth_token}"}

    @task(3)
    def query_case_timeline(self):
        """Simulate viewing timelines for ingested evidence."""
        if not self.auth_token:
            return
        
        # Querying for a simulated evidence ID
        self.client.get("/api/v1/timeline/EV-TRUST-1", headers=self.headers, name="/timeline/{id}")

    @task(1)
    def upload_evidence_media(self):
        """Simulate media file uploads to the ingestion gateway."""
        if not self.auth_token:
            return

        # Generate mock PNG image payload
        file_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 1024 * 1024 # 1 MB file
        files = {
            "file": ("load_test_img.png", file_data, "image/png")
        }
        
        response = self.client.post(
            "/api/v1/upload",
            data={"case_id": self.case_id},
            files=files,
            headers=self.headers,
            name="/upload"
        )
        
        if response.status_code == 200:
            evidence_id = response.json().get("evidence_id")
            # Immediately trigger forensic analysis
            self.client.post(f"/api/v1/analyze?evidence_id={evidence_id}", headers=self.headers, name="/analyze")

    @task(2)
    def get_trust_score(self):
        """Verify trust score calculations and audit logs."""
        if not self.auth_token:
            return
        self.client.get("/api/v1/trust-score/EV-TRUST-1", headers=self.headers, name="/trust-score/{id}")
