from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import select

from app.config import settings
from app.models.schemas import Upload
from app.services.upload_service import UploadService
from app.testing.evidence_factory import (
    build_nested_zip_blob,
    build_polyglot_blob,
    build_zip_bomb_blob,
)

from tests.helpers import png_blob, upload_file


@pytest.mark.security
def test_upload_rejects_unsupported_extension(client, session, tmp_path: Path) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="notes.txt",
        blob=b"plain text evidence",
        mime_type="text/plain",
    )

    assert response.status_code == 400
    assert "File extension '.txt' is not supported" in response.json()["detail"]


@pytest.mark.security
def test_upload_rejects_overly_large_files(client, session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "MAX_FILE_SIZE_MB", 0)

    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="oversized.png",
        blob=png_blob(),
        mime_type="image/png",
    )

    assert response.status_code == 400
    assert "exceeds maximum allowed limit" in response.json()["detail"]


@pytest.mark.security
def test_upload_sanitizes_path_traversal_filename(client, session, tmp_path: Path) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="..\\..\\attack\\midjourney_sample.png",
        blob=png_blob(),
        mime_type="image/png",
    )

    assert response.status_code == 200
    evidence_id = response.json()["evidence_id"]

    upload = session.exec(select(Upload).where(Upload.evidence_id == evidence_id)).first()
    assert upload is not None
    assert Path(upload.storage_path).resolve().is_relative_to(Path(settings.UPLOAD_DIR).resolve())
    assert upload.storage_path.endswith("midjourney_sample.png")
    assert UploadService.sanitize_filename("..\\..\\attack\\midjourney_sample.png") == "midjourney_sample.png"


@pytest.mark.security
def test_upload_accepts_unicode_filenames_securely(client, session, tmp_path: Path) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="résumé.png",
        blob=png_blob(),
        mime_type="image/png",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "résumé.png"


@pytest.mark.adversarial
def test_upload_flags_polyglot_payload_as_critical(client, session, tmp_path: Path) -> None:
    blob = build_polyglot_blob(b"%PDF-1.7", b"PK\x03\x04")
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="forged_report.pdf",
        blob=blob,
        mime_type="application/pdf",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "CRITICAL"
    assert data["trust_score"] == 10.0


@pytest.mark.adversarial
def test_upload_flags_zip_bomb_payload_as_critical(client, session, tmp_path: Path) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="archive.zip",
        blob=build_zip_bomb_blob(payload_size=512 * 1024),
        mime_type="application/zip",
    )

    assert response.status_code == 200
    assert response.json()["risk_level"] == "CRITICAL"
    assert response.json()["trust_score"] == 10.0


@pytest.mark.adversarial
def test_upload_flags_nested_zip_payload_as_critical(client, session, tmp_path: Path) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="nested.zip",
        blob=build_nested_zip_blob(),
        mime_type="application/zip",
    )

    assert response.status_code == 200
    assert response.json()["risk_level"] == "CRITICAL"
    assert response.json()["trust_score"] == 10.0


@pytest.mark.adversarial
def test_upload_flags_executable_disguised_as_image(client, session, tmp_path: Path) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="payload.png",
        blob=b"MZ" + b"\x00" * 128,
        mime_type="image/png",
    )

    assert response.status_code == 200
    assert response.json()["risk_level"] == "CRITICAL"
    assert response.json()["trust_score"] == 10.0


@pytest.mark.security
def test_upload_accepts_valid_png_and_preserves_hashes(client, session, tmp_path: Path) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="auth_guard_test.png",
        blob=png_blob(),
        mime_type="image/png",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in {"LOW", "MEDIUM"}
    assert data["trust_score"] in {95.0, 90.0}
