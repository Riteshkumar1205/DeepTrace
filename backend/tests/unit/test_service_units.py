from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlmodel import select

from app.models.schemas import (
    AIAttributionResult,
    Case,
    BlockchainRecord,
    DeepfakeResult,
    Evidence,
    ForensicsResult,
    Hashes,
    MetadataRecord,
    Organization,
    ProvenanceRecord,
    Upload,
    User,
)
from app.services.blockchain_assessment import BlockchainAssessmentService
from app.services.deepfake_assessment import DeepfakeAssessmentService
from app.services.forensics_summary import ForensicsSummaryService
from app.services.hashing_service import HashingService
from app.services.provenance_service import ProvenanceService
from app.services.trust_service import TrustService
from app.services.upload_service import UploadService


def test_hashing_service_password_round_trip() -> None:
    hashed = HashingService.hash_password("correct horse battery staple")
    assert HashingService.verify_password("correct horse battery staple", hashed)
    assert not HashingService.verify_password("wrong", hashed)


def test_hashing_service_file_hashes_are_deterministic(tmp_path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"deterministic payload")

    first = HashingService.calculate_crypto_hashes(str(path))
    second = HashingService.calculate_crypto_hashes(str(path))

    assert first == second
    assert len(first[0]) == 32
    assert len(first[1]) == 64
    assert len(first[2]) == 128


def test_upload_service_sanitizes_traversal_and_keeps_extension() -> None:
    assert UploadService.sanitize_filename("..\\..\\evil.png") == "evil.png"
    assert UploadService.sanitize_filename("../nested/voice.wav") == "voice.wav"


def test_upload_service_magic_bytes_detects_mismatch(tmp_path) -> None:
    path = tmp_path / "spoofed.png"
    path.write_bytes(b"%PDF-1.7\nrest of payload")

    assert not UploadService.validate_magic_bytes(str(path), "spoofed.png")


def test_upload_service_detects_polyglot_payload() -> None:
    payload = b"%PDF-1.7\n" + b"X" * 32 + b"PK\x03\x04"
    verdict = UploadService._looks_like_polyglot(payload)
    assert verdict is True


def test_provenance_service_identifies_verified_owner(tmp_path) -> None:
    path = tmp_path / "signed.pdf"
    path.write_bytes(
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"c2pa content credentials\n"
        b"trailer\n<<>>\n%%EOF"
    )

    assessment = ProvenanceService.assess_provenance(
        str(path),
        metadata={
            "creator": "Acme Provenance CA",
            "device": "Camera X",
            "editing_history": [{"action": "signed", "software": "Signer"}],
        },
        blockchain_verified=True,
    )

    assert assessment["has_manifest"] is True
    assert assessment["manifest_valid"] is True
    assert assessment["ownership_classification"] == "VERIFIED OWNER"
    assert assessment["confidence_score"] >= 80
    assert "Blockchain custody verification" in assessment["verification_method"]


def test_provenance_service_flags_ai_generation_from_filename(tmp_path) -> None:
    path = tmp_path / "midjourney_sample.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)

    assessment = ProvenanceService.assess_provenance(str(path))

    assert assessment["ai_generation_signals"]["present"] is True
    assert assessment["ownership_classification"] == "PROBABLE OWNER"


def test_blockchain_assessment_without_record_returns_unregistered() -> None:
    assessment = BlockchainAssessmentService.build(None)

    assert assessment["anchored"] is False
    assert assessment["verification_status"] == "UNREGISTERED"
    assert assessment["ownership_classification"] == "UNKNOWN OWNER"


def test_blockchain_assessment_with_context_refines_confidence() -> None:
    now = datetime(2026, 6, 11, tzinfo=timezone.utc)

    class Record:
        chain_name = "Polygon PoS (Mainnet Anchor)"
        block_number = 45890000
        transaction_hash = "0x123"
        registered_owner = "0xabc"
        verification_status = "VERIFIED OWNER"
        created_at = now

    assessment = BlockchainAssessmentService.build(
        Record(),
        evidence_hash="deadbeef",
        provenance_assessment={"ownership_classification": "VERIFIED OWNER"},
        trust_score=92.0,
    )

    assert assessment["anchored"] is True
    assert assessment["confidence_score"] >= 95
    assert assessment["anchor_strength"] >= 97
    assert assessment["ownership_classification"] == "VERIFIED OWNER"


def test_deepfake_assessment_classifies_audio_and_explainability() -> None:
    assessment = DeepfakeAssessmentService.build(
        "audio",
        {
            "model_name": "VoiceResNet",
            "deepfake_probability": 0.91,
            "confidence": 88.0,
            "heatmap_path": "/tmp/heatmap.jpg",
            "explainability": {
                "synthetic_robotics_index": 8.8,
                "harmonic_peaks_deviation": 12.4,
            },
        },
    )

    assert assessment["risk_level"] == "CRITICAL"
    assert assessment["tampered"] is True
    assert assessment["heatmap_available"] is True
    assert any("Synthetic robotics index" in item for item in assessment["supporting_evidence"])


def test_forensics_summary_aggregates_document_findings() -> None:
    summary = ForensicsSummaryService.build_from_service_result(
        "document",
        {
            "tampered": True,
            "confidence": 87.0,
            "reasons": ["JavaScript payload detected"],
            "details": {"javascript_count": 1, "open_action_count": 1},
        },
    )

    assert summary["tampered"] is True
    assert summary["file_type"] == "document"
    assert "PDFID/PeePDF-style structural audit" in summary["verification_method"]
    assert any("JavaScript objects" in item for item in summary["supporting_evidence"])


def test_forensics_summary_from_records_handles_multiple_results() -> None:
    summary = ForensicsSummaryService.build_from_service_result(
        "image",
        {
            "details": {
                "ela": {"tampered": True, "confidence": 91.0, "output_image_path": "/tmp/ela.jpg"},
                "noise": {"tampered": False, "confidence": 88.0, "statistics": {"anomaly_ratio": 0.12}},
                "clone_detection": {"tampered": False, "confidence": 95.0, "modified_regions": []},
                "jpeg_ghost": {"tampered": False, "confidence": 90.0, "detected_original_quality": 90},
            }
        },
    )

    assert summary["tampered"] is True
    assert summary["file_type"] == "image"
    assert summary["modified_regions"] == []
    assert any("ELA energy delta" in item for item in summary["supporting_evidence"])


def test_trust_service_scores_critical_deepfake_to_zero(session) -> None:
    org = session.exec(select(Organization).where(Organization.name == "Test Security Unit")).first()
    user = session.exec(select(User).where(User.email == "tester@deeptrace.ai")).first()
    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert org is not None
    assert user is not None
    assert case is not None

    evidence = Evidence(
        id="EV-TRUST-1",
        case_id=case.id,
        filename="fake_stable_diffusion.png",
        file_type="image",
        mime_type="image/png",
        size_bytes=1024,
        status="completed",
        risk_level="LOW",
        trust_score=95.0,
    )
    session.add(evidence)
    session.add(Upload(
        evidence_id=evidence.id,
        storage_path="storage/uploads/fake_stable_diffusion.png",
        integrity_valid=True,
        malware_scan_passed=True,
        duplicate_detected=False,
    ))
    session.add(Hashes(
        evidence_id=evidence.id,
        md5="a",
        sha256="b",
        sha512="c",
    ))
    session.add(DeepfakeResult(
        evidence_id=evidence.id,
        model_name="ViT",
        deepfake_probability=0.95,
        confidence=92.0,
        explainability={"synthetic_robotics_index": 9.5},
    ))
    session.add(AIAttributionResult(
        evidence_id=evidence.id,
        predicted_source="Stable Diffusion",
        probability=0.98,
        confidence=94.0,
        indicators={"metadata_signals": ["Filename indicates Stable Diffusion generation"]},
    ))
    session.commit()

    assessment = TrustService.calculate_score(session, evidence.id)

    assert assessment["trust_score"] == 0.0
    assert assessment["risk_level"] == "CRITICAL"
    assert any("Deepfake detected" in item for item in assessment["reasons"])
