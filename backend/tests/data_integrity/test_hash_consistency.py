from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import select

from app.models.schemas import Hashes, Upload
from app.services.hashing_service import HashingService
from tests.helpers import auth_headers, png_blob, upload_file


@pytest.mark.data_integrity
def test_stored_hashes_match_recomputed_hashes(client, session, tmp_path: Path) -> None:
    response = upload_file(
        client,
        session,
        tmp_path=tmp_path,
        filename="hash_integrity.png",
        blob=png_blob(),
        mime_type="image/png",
    )
    evidence_id = response.json()["evidence_id"]

    record = session.exec(select(Hashes).where(Hashes.evidence_id == evidence_id)).first()
    assert record is not None

    headers = auth_headers(client)
    upload = session.exec(select(Upload).where(Upload.evidence_id == evidence_id)).first()
    assert upload is not None
    recomputed = HashingService.calculate_crypto_hashes(upload.storage_path)

    assert (record.md5, record.sha256, record.sha512) == recomputed

    verify = client.post(
        "/api/v1/verify-hash",
        json={"sha256": record.sha256},
        headers=headers,
    )
    assert verify.status_code == 200
    payload = verify.json()
    assert payload["match_found"] is True
    assert payload["evidence"]["id"] == evidence_id
