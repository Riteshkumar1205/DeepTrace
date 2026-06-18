import os
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select
from sqlmodel.pool import StaticPool

from app.main import app
from app.db import get_db
from app.models.schemas import User, Organization, Case, Evidence
from app.services.hashing_service import HashingService

# Create an in-memory SQLite database for testing
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

@pytest.fixture(name="session")
def session_fixture():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        # Seed test Organization
        org = Organization(name="Test Security Unit")
        session.add(org)
        session.commit()
        session.refresh(org)

        # Seed test user
        user = User(
            email="tester@deeptrace.ai",
            hashed_password=HashingService.hash_password("testpassword"),
            full_name="Jane Doe",
            role="analyst",
            organization_id=org.id
        )
        session.add(user)
        session.commit()
        session.refresh(user)

        # Seed case
        case = Case(
            case_number="CASE-2026-TEST",
            title="Test Case",
            description="Testing suite workspace",
            creator_id=user.id
        )
        session.add(case)
        session.commit()

        yield session
    SQLModel.metadata.drop_all(engine)

@pytest.fixture(name="client")
def client_fixture(session):
    def get_db_override():
        return session

    app.dependency_overrides[get_db] = get_db_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()

def test_auth_login(client):
    # Test valid login
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_auth_login_rejects_invalid_credentials(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "wrong-password"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Incorrect email or password"


def test_auth_register_rejects_duplicate_email(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "tester@deeptrace.ai",
            "password": "testpassword",
            "full_name": "Jane Doe",
            "organization_name": "Test Security Unit",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "User already registered"


def test_auth_register(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "new.analyst@deeptrace.ai",
            "password": "strong-password",
            "full_name": "New Analyst",
            "organization_name": "New Security Org",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert data["access_token"]

def test_create_case(client):
    # 1. Login to get token
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # 2. Create case
    response = client.post(
        "/api/v1/cases",
        json={"title": "Intrusion Analysis Campaign", "description": "Analyzing threat uploads"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Intrusion Analysis Campaign"
    assert "case_number" in data

def test_upload_and_analyze(client, session):
    # 1. Login to get token
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # 2. Fetch seeded case
    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    # Create dummy PNG file to upload (with valid PNG signature headers)
    temp_png = "test_image.png"
    with open(temp_png, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)

    try:
        # 3. Upload
        with open(temp_png, "rb") as f:
            response = client.post(
                "/api/v1/upload",
                data={"case_id": case.id},
                files={"file": (temp_png, f, "image/png")},
                headers={"Authorization": f"Bearer {token}"}
            )
        assert response.status_code == 200
        upload_data = response.json()
        assert upload_data["status"] == "success"
        evidence_id = upload_data["evidence_id"]

        # 4. Analyze (this now triggers ELA + Noise + C2PA provenance extraction)
        response = client.post(
            f"/api/v1/analyze?evidence_id={evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "completed"

        # 5. Retrieve analysis detailed logs and assert forensics & provenance results are created
        response = client.get(
            f"/api/v1/analysis/{evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        detail = response.json()
        assert "forensics" in detail
        assert len(detail["forensics"]) > 0
        assert any(f["engine_name"] == "Image ELA" for f in detail["forensics"])
        assert "forensics_summary" in detail
        assert detail["forensics_summary"] is not None
        assert detail["forensics_summary"]["file_type"] == "image"
        assert "verification_method" in detail["forensics_summary"]
        
        # Verify provenance record was populated
        assert "provenance" in detail
        assert detail["provenance"] is not None
        assert detail["provenance"]["verification_method"].startswith("Binary manifest scan")
        assert "provenance_assessment" in detail
        assert detail["provenance_assessment"] is not None
        assert detail["provenance_assessment"]["ownership_classification"] == "UNKNOWN OWNER"
        assert "trust_assessment" in detail
        assert detail["trust_assessment"] is not None
        assert detail["trust_assessment"]["verdict"] in ["HIGH TRUST", "MODERATE TRUST", "LOW TRUST"]
        assert detail["trust_assessment"]["verification_methods"]

        # Verify deepfake & AI attribution populated
        assert "deepfake" in detail
        assert detail["deepfake"] is not None
        assert detail["deepfake"]["deepfake_probability"] == 0.05
        assert "ai_attribution" in detail
        assert detail["ai_attribution"] is not None
        assert detail["ai_attribution"]["predicted_source"] == "Human / Camera Original"

        # 6. Verify POST /verify-c2pa endpoint directly
        response = client.post(
            f"/api/v1/verify-c2pa?evidence_id={evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        prov_data = response.json()
        assert "verification_method" in prov_data
        assert prov_data["verification_method"].startswith("Binary manifest scan")
        assert "manifest_valid" in prov_data
        assert "ownership_classification" in prov_data

        # 7. Retrieve Trust Score and check calculations
        response = client.get(
            f"/api/v1/trust-score/{evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        score_data = response.json()
        assert "trust_score" in score_data
        assert score_data["trust_score"] > 0
        assert "trust_assessment" in score_data or "verdict" in score_data

    finally:
        # Cleanup
        if os.path.exists(temp_png):
            os.remove(temp_png)


def test_upload_rejects_unsupported_extension(client, session):
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    temp_txt = "notes.txt"
    with open(temp_txt, "wb") as f:
        f.write(b"plain text evidence")

    try:
        with open(temp_txt, "rb") as f:
            response = client.post(
                "/api/v1/upload",
                data={"case_id": case.id},
                files={"file": (temp_txt, f, "text/plain")},
                headers={"Authorization": f"Bearer {token}"}
            )
        assert response.status_code == 400
        assert "File extension '.txt' is not supported" in response.json()["detail"]
    finally:
        if os.path.exists(temp_txt):
            os.remove(temp_txt)


def test_upload_marks_magic_bytes_mismatch_as_critical(client, session):
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    temp_png = "spoofed_image.png"
    with open(temp_png, "wb") as f:
        f.write(b"%PDF-1.4\n" + b"\x00" * 200)

    try:
        with open(temp_png, "rb") as f:
            response = client.post(
                "/api/v1/upload",
                data={"case_id": case.id},
                files={"file": (temp_png, f, "image/png")},
                headers={"Authorization": f"Bearer {token}"}
            )
        assert response.status_code == 200
        payload = response.json()
        assert payload["risk_level"] == "CRITICAL"
        assert payload["trust_score"] == 10.0
    finally:
        if os.path.exists(temp_png):
            os.remove(temp_png)


def test_document_forensics_summary(client, session):
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    temp_pdf = "tampered_report.pdf"
    pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert('x')) >> >>\nendobj\n"
        b"trailer\n<<>>\n%%EOF"
    )
    with open(temp_pdf, "wb") as f:
        f.write(pdf_bytes)

    try:
        with open(temp_pdf, "rb") as f:
            response = client.post(
                "/api/v1/upload",
                data={"case_id": case.id},
                files={"file": (temp_pdf, f, "application/pdf")},
                headers={"Authorization": f"Bearer {token}"}
            )
        assert response.status_code == 200
        evidence_id = response.json()["evidence_id"]

        response = client.post(
            f"/api/v1/analyze?evidence_id={evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["forensics_summary"]["file_type"] == "document"

        response = client.get(
            f"/api/v1/analysis/{evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        detail = response.json()
        assert detail["forensics_summary"]["tampered"] is True
        assert "PDFID/PeePDF-style structural audit" in detail["forensics_summary"]["verification_method"]
        assert any("JavaScript" in reason for reason in detail["forensics_summary"]["supporting_evidence"])
        assert "provenance_assessment" in detail
        assert detail["provenance_assessment"]["ownership_classification"] == "UNKNOWN OWNER"
    finally:
        if os.path.exists(temp_pdf):
            os.remove(temp_pdf)


def test_ai_provenance_assessment(client, session):
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    temp_png = "midjourney_sample.png"
    with open(temp_png, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)

    try:
        with open(temp_png, "rb") as f:
            response = client.post(
                "/api/v1/upload",
                data={"case_id": case.id},
                files={"file": (temp_png, f, "image/png")},
                headers={"Authorization": f"Bearer {token}"}
            )
        assert response.status_code == 200
        evidence_id = response.json()["evidence_id"]

        response = client.post(
            f"/api/v1/analyze?evidence_id={evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        detail = response.json()
        assert detail["provenance_assessment"]["ownership_classification"] == "PROBABLE OWNER"
        assert detail["provenance_assessment"]["confidence_score"] > 0

        response = client.post(
            f"/api/v1/verify-c2pa?evidence_id={evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        prov_data = response.json()
        assert prov_data["ownership_classification"] == "PROBABLE OWNER"
        assert prov_data["verification_status"] == "PROBABLE OWNER"
    finally:
        if os.path.exists(temp_png):
            os.remove(temp_png)


def test_audio_deepfake_assessment(client, session):
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    temp_wav = "fake_cloned_voice.wav"
    with open(temp_wav, "wb") as f:
        f.write(b"RIFF" + b"\x00" * 40 + b"fake_cloned_voice")

    try:
        with open(temp_wav, "rb") as f:
            response = client.post(
                "/api/v1/upload",
                data={"case_id": case.id},
                files={"file": (temp_wav, f, "audio/wav")},
                headers={"Authorization": f"Bearer {token}"}
            )
        assert response.status_code == 200
        evidence_id = response.json()["evidence_id"]

        response = client.post(
            f"/api/v1/analyze?evidence_id={evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        detail = response.json()
        assert detail["deepfake_assessment"]["risk_level"] == "CRITICAL"
        assert detail["deepfake_assessment"]["verification_method"].startswith("Voice cloning")
        assert any("Synthetic robotics index" in item for item in detail["deepfake_assessment"]["supporting_evidence"])
    finally:
        if os.path.exists(temp_wav):
            os.remove(temp_wav)


def test_deepfake_and_ai_attribution(client, session):
    # 1. Login to get token
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # 2. Fetch seeded case
    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    # Create dummy PNG file to upload (filename triggers deepfake/AI rules)
    temp_png = "fake_stable_diffusion.png"
    with open(temp_png, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)

    try:
        # 3. Upload
        with open(temp_png, "rb") as f:
            response = client.post(
                "/api/v1/upload",
                data={"case_id": case.id},
                files={"file": (temp_png, f, "image/png")},
                headers={"Authorization": f"Bearer {token}"}
            )
        assert response.status_code == 200
        upload_data = response.json()
        assert upload_data["status"] == "success"
        evidence_id = upload_data["evidence_id"]

        # 4. Analyze (triggers deepfake & AI attribution rules due to filename)
        response = client.post(
            f"/api/v1/analyze?evidence_id={evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "completed"

        # 5. Retrieve analysis detailed logs
        response = client.get(
            f"/api/v1/analysis/{evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        detail = response.json()

        # Check deepfake result (fake filename triggers Xception/ViT probability >= 80% -> drops trust score to 0)
        assert "deepfake" in detail
        assert detail["deepfake"] is not None
        assert detail["deepfake"]["deepfake_probability"] >= 0.80
        assert "deepfake_assessment" in detail
        assert detail["deepfake_assessment"] is not None
        assert detail["deepfake_assessment"]["risk_level"] == "CRITICAL"
        assert detail["deepfake_assessment"]["heatmap_available"] is True
        assert "trust_assessment" in detail
        assert detail["trust_assessment"]["risk_level"] == "CRITICAL"
        assert detail["trust_assessment"]["stability"] == "UNSTABLE"

        # Check AI content attribution
        assert "ai_attribution" in detail
        assert detail["ai_attribution"] is not None
        assert detail["ai_attribution"]["predicted_source"] == "Stable Diffusion"
        assert detail["ai_attribution"]["probability"] >= 0.90

        # Check Trust Score and risk level (should be 0.0 and CRITICAL)
        response = client.get(
            f"/api/v1/trust-score/{evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        score_data = response.json()
        assert score_data["trust_score"] == 0.0
        assert score_data["risk_level"] == "CRITICAL"
        assert any("Deepfake detected" in r for r in score_data["reasons"])
        assert score_data["verdict"] == "LOW TRUST"
        assert score_data["trust_band"] == "RED"

        # 6. Anchor to Blockchain Ledger
        response = client.post(
            f"/api/v1/blockchain/register?evidence_id={evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        bc_data = response.json()
        assert bc_data["evidence_id"] == evidence_id
        assert bc_data["chain_name"] == "Polygon PoS (Mainnet Anchor)"
        assert bc_data["verification_status"] == "VERIFIED OWNER"
        assert "transaction_hash" in bc_data
        assert "block_number" in bc_data
        assert "blockchain_assessment" in bc_data
        assert bc_data["blockchain_assessment"]["anchored"] is True
        assert bc_data["blockchain_assessment"]["ownership_classification"] in ["VERIFIED OWNER", "PROBABLE OWNER"]

        # Verify blockchain details returned in analysis payload
        response = client.get(
            f"/api/v1/analysis/{evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        detail = response.json()
        assert "blockchain" in detail
        assert detail["blockchain"] is not None
        assert detail["blockchain"]["transaction_hash"] == bc_data["transaction_hash"]
        assert "blockchain_assessment" in detail
        assert detail["blockchain_assessment"]["anchored"] is True

        # Verify ledger endpoint provides normalized assessment
        response = client.get(
            f"/api/v1/verify-ledger/{evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        ledger = response.json()
        assert ledger["anchored"] is True
        assert ledger["transaction_hash"] == bc_data["transaction_hash"]

        # 7. Generate and download signed Forensic PDF Report
        response = client.get(
            f"/api/v1/report/{evidence_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert len(response.content) > 0

    finally:
        # Cleanup report if generated
        report_path = os.path.join("storage", "reports", f"report_{evidence_id}.pdf")
        # Since we use default folder config (settings.REPORT_DIR), let's check settings
        from app.config import settings
        full_report_path = os.path.join(settings.REPORT_DIR, f"report_{evidence_id}.pdf")
        if os.path.exists(full_report_path):
            try:
                os.remove(full_report_path)
            except Exception:
                pass
        
        # Cleanup
        if os.path.exists(temp_png):
            os.remove(temp_png)


def test_sensitive_endpoints_require_auth(client, session):
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    temp_png = "auth_guard_test.png"
    with open(temp_png, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)

    try:
        with open(temp_png, "rb") as f:
            upload_response = client.post(
                "/api/v1/upload",
                data={"case_id": case.id},
                files={"file": (temp_png, f, "image/png")},
                headers={"Authorization": f"Bearer {token}"}
            )
        assert upload_response.status_code == 200
        evidence_id = upload_response.json()["evidence_id"]

        assert client.get(f"/api/v1/analysis/{evidence_id}").status_code == 401
        assert client.get(f"/api/v1/trust-score/{evidence_id}").status_code == 401
        assert client.get(f"/api/v1/report/{evidence_id}").status_code == 401
        assert client.get(f"/api/v1/verify-ledger/{evidence_id}").status_code == 401
        assert client.post("/api/v1/verify-hash", json={"sha256": "deadbeef"}).status_code == 401
        assert client.post(f"/api/v1/verify-c2pa?evidence_id={evidence_id}").status_code == 401
    finally:
        if os.path.exists(temp_png):
            os.remove(temp_png)


def test_missing_evidence_returns_404(client):
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    missing_id = str(uuid.uuid4())
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get(f"/api/v1/analysis/{missing_id}", headers=headers).status_code == 404
    assert client.get(f"/api/v1/trust-score/{missing_id}", headers=headers).status_code == 404
    assert client.get(f"/api/v1/report/{missing_id}", headers=headers).status_code == 404
    assert client.get(f"/api/v1/verify-ledger/{missing_id}", headers=headers).status_code == 404


def test_verify_c2pa_rejects_evidence_without_upload_record(client, session):
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    org = session.exec(select(Organization).where(Organization.name == "Test Security Unit")).first()
    user = session.exec(select(User).where(User.email == "tester@deeptrace.ai")).first()
    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert org is not None
    assert user is not None
    assert case is not None

    evidence_id = str(uuid.uuid4())
    session.add(
        Evidence(
            id=evidence_id,
            case_id=case.id,
            filename="orphaned.png",
            file_type="image",
            mime_type="image/png",
            size_bytes=256,
            status="ingested",
            risk_level="LOW",
            trust_score=95.0,
        )
    )
    session.commit()

    response = client.post(
        f"/api/v1/verify-c2pa?evidence_id={evidence_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Evidence files not uploaded properly"
