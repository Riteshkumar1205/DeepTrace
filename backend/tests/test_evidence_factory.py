from pathlib import Path

import pytest

from app.testing.evidence_factory import (
    EvidenceCase,
    build_evidence_blob,
    sanitize_filename,
    write_evidence_file,
)


@pytest.mark.parametrize(
    ("raw_name", "expected"),
    [
        ("sample.png", "sample.png"),
        ("..\\..\\evil.png", "evil.png"),
        ("../nested/voice.wav", "voice.wav"),
        ("subdir/../document.pdf", "document.pdf"),
    ],
    ids=["plain", "windows-traversal", "unix-traversal", "mixed-traversal"],
)
def test_sanitize_filename_strips_path_components(raw_name: str, expected: str) -> None:
    assert sanitize_filename(raw_name) == expected


@pytest.mark.parametrize(
    ("case", "expected_prefix", "expected_contains"),
    [
        (
            EvidenceCase(kind="image", file_type="png", adversarial=False),
            b"\x89PNG\r\n\x1a\n",
            b"IHDR",
        ),
        (
            EvidenceCase(kind="document", file_type="pdf", adversarial=False),
            b"%PDF",
            b"/Catalog",
        ),
        (
            EvidenceCase(kind="audio", file_type="wav", adversarial=False),
            b"RIFF",
            b"WAVE",
        ),
    ],
    ids=["png", "pdf", "wav"],
)
def test_build_evidence_blob_returns_valid_fixture(case: EvidenceCase, expected_prefix: bytes, expected_contains: bytes) -> None:
    blob = build_evidence_blob(case)
    assert blob.startswith(expected_prefix)
    assert expected_contains in blob
    assert len(blob) > 32


def test_build_evidence_blob_can_emit_corrupted_variant() -> None:
    case = EvidenceCase(kind="image", file_type="png", adversarial=True)
    blob = build_evidence_blob(case)
    assert not blob.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(blob) > 0


def test_build_evidence_blob_supports_polyglot_payload() -> None:
    case = EvidenceCase(kind="document", file_type="pdf", adversarial=True, polyglot=True)
    blob = build_evidence_blob(case)
    assert blob.startswith(b"%PDF")
    assert b"PK\x03\x04" in blob


def test_write_evidence_file_normalizes_filename_and_stays_in_directory(tmp_path: Path) -> None:
    case = EvidenceCase(kind="image", file_type="png", adversarial=False)
    blob = build_evidence_blob(case)

    target = write_evidence_file(tmp_path, "..\\..\\attack\\midjourney_sample.png", blob)

    assert target.parent == tmp_path
    assert target.name == "midjourney_sample.png"
    assert target.read_bytes() == blob
    assert tmp_path.resolve() in target.resolve().parents or target.resolve().parent == tmp_path.resolve()
