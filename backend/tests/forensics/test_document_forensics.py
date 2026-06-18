from __future__ import annotations

from pathlib import Path

import pytest

from app.services.document_forensics import DocumentForensicsService
from tests.helpers import pdf_blob, write_temp_file


@pytest.mark.forensics
def test_document_forensics_detects_javascript_and_open_action(tmp_path: Path) -> None:
    target = write_temp_file(tmp_path, "tampered_report.pdf", pdf_blob(javascript=True))

    result = DocumentForensicsService.analyze_document(str(target))

    assert result["tampered"] is True
    assert result["confidence"] >= 88.0
    assert result["details"]["javascript_count"] >= 1
    assert result["details"]["open_action_count"] >= 1
    assert any("Embedded scripts" in reason for reason in result["reasons"])


@pytest.mark.forensics
def test_document_forensics_accepts_clean_pdf(tmp_path: Path) -> None:
    target = write_temp_file(tmp_path, "clean_report.pdf", pdf_blob())

    result = DocumentForensicsService.analyze_document(str(target))

    assert result["tampered"] is False
    assert result["confidence"] == 95.0
    assert result["details"]["javascript_count"] == 0
    assert any("No active script tags" in reason for reason in result["reasons"])
