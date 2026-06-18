from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import select

from app.models.schemas import Evidence
from app.services.metadata_service import MetadataService
from app.services.reporting_service import ReportingService
from tests.helpers import auth_headers, png_blob, upload_file


@pytest.mark.chaos
def test_analysis_marks_evidence_failed_when_metadata_stage_crashes(client, session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="chaos.png",
        blob=png_blob(),
        mime_type="image/png",
    )
    evidence_id = response.json()["evidence_id"]

    def boom(*args, **kwargs):
        raise RuntimeError("metadata subsystem offline")

    monkeypatch.setattr(MetadataService, "extract_metadata", boom)

    headers = auth_headers(client)
    result = client.post(f"/api/v1/analyze?evidence_id={evidence_id}", headers=headers)

    assert result.status_code == 500
    assert "Forensic analysis pipeline failed" in result.json()["detail"]

    evidence = session.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
    assert evidence is not None
    assert evidence.status == "failed"


@pytest.mark.chaos
def test_report_endpoint_fails_closed_when_report_generation_returns_false(client, session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="report_fail.png",
        blob=png_blob(),
        mime_type="image/png",
    )
    evidence_id = response.json()["evidence_id"]
    headers = auth_headers(client)

    analyze = client.post(f"/api/v1/analyze?evidence_id={evidence_id}", headers=headers)
    assert analyze.status_code == 200

    monkeypatch.setattr(ReportingService, "generate_pdf_report", lambda *args, **kwargs: False)

    report = client.get(f"/api/v1/report/{evidence_id}", headers=headers)
    assert report.status_code == 500
    assert report.json()["detail"] == "Failed to generate PDF report"
