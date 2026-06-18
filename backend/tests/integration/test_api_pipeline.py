from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlmodel import select

from app.config import settings
from app.models.schemas import Upload
from tests.helpers import auth_headers, png_blob, upload_file


@pytest.mark.integration
def test_full_analysis_pipeline(client, session, tmp_path: Path) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="midjourney_sample.png",
        blob=png_blob(),
        mime_type="image/png",
    )
    assert response.status_code == 200
    upload_payload = response.json()
    evidence_id = upload_payload["evidence_id"]

    headers = auth_headers(client)
    analyze = client.post(f"/api/v1/analyze?evidence_id={evidence_id}", headers=headers)
    assert analyze.status_code == 200
    analysis_payload = analyze.json()
    assert analysis_payload["status"] == "completed"
    assert analysis_payload["forensics_summary"]["file_type"] == "image"
    assert analysis_payload["provenance_assessment"]["ownership_classification"] in {
        "PROBABLE OWNER",
        "UNKNOWN OWNER",
    }
    assert analysis_payload["trust_assessment"]["evidence_id"] == evidence_id

    detail = client.get(f"/api/v1/analysis/{evidence_id}", headers=headers)
    assert detail.status_code == 200
    detail_payload = detail.json()
    assert detail_payload["forensics_summary"]["file_type"] == "image"
    assert detail_payload["deepfake_assessment"]["file_type"] == "image"
    assert detail_payload["trust_assessment"]["evidence_id"] == evidence_id
    assert len(detail_payload["forensics"]) > 0
    assert Path(detail_payload["upload"]["storage_path"]).resolve().is_relative_to(Path(settings.UPLOAD_DIR).resolve())

    c2pa = client.post(f"/api/v1/verify-c2pa?evidence_id={evidence_id}", headers=headers)
    assert c2pa.status_code == 200
    c2pa_payload = c2pa.json()
    assert c2pa_payload["evidence_id"] == evidence_id
    assert "verification_method" in c2pa_payload

    trust = client.get(f"/api/v1/trust-score/{evidence_id}", headers=headers)
    assert trust.status_code == 200
    trust_payload = trust.json()
    assert trust_payload["evidence_id"] == evidence_id
    assert "verification_methods" in trust_payload

    report = client.get(f"/api/v1/report/{evidence_id}", headers=headers)
    assert report.status_code == 200
    assert report.headers["content-type"] == "application/pdf"
    assert len(report.content) > 0

    timeline = client.get(f"/api/v1/timeline/{evidence_id}", headers=headers)
    assert timeline.status_code == 200
    assert len(timeline.json()) >= 2

    upload_row = session.exec(select(Upload).where(Upload.evidence_id == evidence_id)).first()
    assert upload_row is not None
    assert upload_row.integrity_valid is True


@pytest.mark.integration
def test_api_rejects_report_access_without_auth(client, session, tmp_path: Path) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="auth_guard_test.png",
        blob=png_blob(),
        mime_type="image/png",
    )
    evidence_id = response.json()["evidence_id"]

    assert client.get(f"/api/v1/report/{evidence_id}").status_code == 401
    assert client.get(f"/api/v1/analysis/{evidence_id}").status_code == 401
