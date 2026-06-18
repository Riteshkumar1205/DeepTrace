from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import select

from app.models.schemas import Case, DocumentTrace, UserSession
from tests.helpers import auth_headers, png_blob, upload_file, write_temp_file


@pytest.mark.chain_of_custody
def test_chain_of_custody_records_upload_analysis_and_blockchain(client, session, tmp_path: Path) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="chain_audit.png",
        blob=png_blob(),
        mime_type="image/png",
    )
    evidence_id = response.json()["evidence_id"]
    headers = auth_headers(client)

    analyze = client.post(f"/api/v1/analyze?evidence_id={evidence_id}", headers=headers)
    assert analyze.status_code == 200

    anchor = client.post(f"/api/v1/blockchain/register?evidence_id={evidence_id}", headers=headers)
    assert anchor.status_code == 200

    timeline = client.get(f"/api/v1/timeline/{evidence_id}", headers=headers)
    assert timeline.status_code == 200
    entries = timeline.json()
    assert [entry["operation"] for entry in entries[:3]] == [
        "Upload & Ingestion",
        "Deep Forensic Analysis",
        "Blockchain Ledger Anchor",
    ]
    assert all(entry["hash_value"] for entry in entries)
    assert len({entry["hash_value"] for entry in entries}) == 1


@pytest.mark.chain_of_custody
def test_document_trace_captures_session_and_analysis_details(client, session, tmp_path: Path) -> None:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "tester@deeptrace.ai", "password": "testpassword"},
    )
    assert login.status_code == 200
    login_data = login.json()
    assert login_data["session_id"]
    token = login_data["access_token"]

    session_row = session.exec(
        select(UserSession).where(UserSession.session_id == login_data["session_id"])
    ).first()
    assert session_row is not None
    assert session_row.user_email == "tester@deeptrace.ai"

    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    token_headers = {"Authorization": f"Bearer {token}"}
    temp_file = write_temp_file(tmp_path, "forensic_claim_original.png", png_blob())
    with temp_file.open("rb") as fh:
        response = client.post(
            "/api/v1/upload",
            data={"case_id": case.id},
            files={"file": ("forensic_claim_original.png", fh, "image/png")},
            headers=token_headers,
        )
    assert response.status_code == 200
    upload_data = response.json()
    assert upload_data["session_id"] == login_data["session_id"]
    assert upload_data["trace_id"]

    evidence_id = upload_data["evidence_id"]
    analyze = client.post(
        f"/api/v1/analyze?evidence_id={evidence_id}",
        headers=token_headers,
    )
    assert analyze.status_code == 200
    analyze_data = analyze.json()
    assert analyze_data["trace_id"] is not None

    trace = session.exec(select(DocumentTrace).where(DocumentTrace.evidence_id == evidence_id)).first()
    assert trace is not None
    assert trace.session_id == login_data["session_id"]
    assert trace.filename == "forensic_claim_original.png"
    assert trace.extracted_content_summary
    assert trace.model_input_prompt
    assert trace.processing_steps
    assert trace.model_output
    assert trace.classifications
    assert trace.extracted_entities
    assert trace.token_usage.get("total_tokens", 0) > 0
    assert trace.processing_duration_ms is not None
