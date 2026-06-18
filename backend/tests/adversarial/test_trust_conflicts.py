from __future__ import annotations

import pytest
from sqlmodel import select

from app.models.schemas import AIAttributionResult, Case, DeepfakeResult, Evidence, Hashes, MetadataRecord, ProvenanceRecord, Upload
from app.services.trust_assessment import TrustAssessmentService
from app.services.trust_service import TrustService


@pytest.mark.adversarial
def test_conflicting_evidence_remains_explainable(session) -> None:
    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    evidence = Evidence(
        id="EV-ADV-1",
        case_id=case.id,
        filename="stable_diffusion_conflict.png",
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
        storage_path="storage/uploads/stable_diffusion_conflict.png",
        integrity_valid=True,
        malware_scan_passed=True,
        duplicate_detected=False,
    ))
    session.add(Hashes(
        evidence_id=evidence.id,
        md5="1",
        sha256="2",
        sha512="3",
    ))
    session.add(MetadataRecord(
        evidence_id=evidence.id,
        creator="Unknown",
        software_used="Stable Diffusion",
        raw_metadata={},
    ))
    session.add(ProvenanceRecord(
        evidence_id=evidence.id,
        has_manifest=False,
        manifest_valid=False,
        creator=None,
        device=None,
        editing_history=[],
    ))
    session.add(DeepfakeResult(
        evidence_id=evidence.id,
        model_name="ViT-B/16",
        deepfake_probability=0.91,
        confidence=90.0,
        explainability={"spliced_regions": ["mouth_boundary"]},
    ))
    session.add(AIAttributionResult(
        evidence_id=evidence.id,
        predicted_source="Stable Diffusion",
        probability=0.97,
        confidence=93.0,
        indicators={"metadata_signals": ["Filename indicates Stable Diffusion generation"]},
    ))
    session.commit()

    assessment = TrustService.calculate_score(session, evidence.id)

    assert assessment["trust_score"] == 0.0
    assert assessment["risk_level"] == "CRITICAL"
    assert len(assessment["reasons"]) >= 2


@pytest.mark.adversarial
def test_ai_generated_content_without_c2pa_stays_below_low_trust(session) -> None:
    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    evidence = Evidence(
        id="EV-ADV-2",
        case_id=case.id,
        filename="dalle_artwork.png",
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
        storage_path="storage/uploads/dalle_artwork.png",
        integrity_valid=True,
        malware_scan_passed=True,
        duplicate_detected=False,
    ))
    session.add(Hashes(
        evidence_id=evidence.id,
        md5="1",
        sha256="2",
        sha512="3",
    ))
    session.add(AIAttributionResult(
        evidence_id=evidence.id,
        predicted_source="DALL-E",
        probability=0.97,
        confidence=93.0,
        indicators={"metadata_signals": ["Filename indicates DALL-E generation"]},
    ))
    session.commit()

    assessment = TrustService.calculate_score(session, evidence.id)

    assert assessment["trust_score"] < 85
    assert assessment["risk_level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert any("Unverified AI-generated content source" in reason for reason in assessment["reasons"])


@pytest.mark.adversarial
def test_claiming_original_when_content_is_synthetic_is_explicitly_flagged(session) -> None:
    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    evidence = Evidence(
        id="EV-ADV-3",
        case_id=case.id,
        filename="original_camera_photo.png",
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
        storage_path="storage/uploads/original_camera_photo.png",
        integrity_valid=True,
        malware_scan_passed=True,
        duplicate_detected=False,
    ))
    session.add(Hashes(
        evidence_id=evidence.id,
        md5="4",
        sha256="5",
        sha512="6",
    ))
    session.add(MetadataRecord(
        evidence_id=evidence.id,
        creator="Unknown",
        software_used="Stable Diffusion",
        raw_metadata={},
    ))
    session.add(ProvenanceRecord(
        evidence_id=evidence.id,
        has_manifest=False,
        manifest_valid=False,
        creator=None,
        device=None,
        editing_history=[],
    ))
    session.add(DeepfakeResult(
        evidence_id=evidence.id,
        model_name="ViT-B/16",
        deepfake_probability=0.60,
        confidence=88.0,
        explainability={"spliced_regions": ["mouth_boundary"]},
    ))
    session.add(AIAttributionResult(
        evidence_id=evidence.id,
        predicted_source="Stable Diffusion",
        probability=0.97,
        confidence=93.0,
        indicators={"metadata_signals": ["Filename indicates Stable Diffusion generation"]},
    ))
    session.commit()

    assessment = TrustService.calculate_score(session, evidence.id)
    trust = TrustAssessmentService.build(session, evidence.id)

    assert assessment["claim_assessment"]["conflict_type"] == "FAKE CLAIM OVER ORIGINAL"
    assert assessment["claim_assessment"]["is_conflict"] is True
    assert assessment["trust_score"] <= 10.0
    assert any("Claim conflict detected" in reason for reason in assessment["reasons"])
    assert trust["claim_assessment"]["conflict_type"] == "FAKE CLAIM OVER ORIGINAL"


@pytest.mark.adversarial
def test_claiming_fake_when_content_is_original_is_explicitly_flagged(session) -> None:
    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    evidence = Evidence(
        id="EV-ADV-4",
        case_id=case.id,
        filename="fake_generated_art.png",
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
        storage_path="storage/uploads/fake_generated_art.png",
        integrity_valid=True,
        malware_scan_passed=True,
        duplicate_detected=False,
    ))
    session.add(Hashes(
        evidence_id=evidence.id,
        md5="7",
        sha256="8",
        sha512="9",
    ))
    session.add(MetadataRecord(
        evidence_id=evidence.id,
        creator="Camera Operator",
        software_used="Camera Firmware",
        raw_metadata={},
    ))
    session.add(ProvenanceRecord(
        evidence_id=evidence.id,
        has_manifest=True,
        manifest_valid=True,
        creator="Newsroom",
        device="Camera X",
        editing_history=[],
    ))
    session.add(DeepfakeResult(
        evidence_id=evidence.id,
        model_name="ViT-B/16",
        deepfake_probability=0.05,
        confidence=96.0,
        explainability={},
    ))
    session.add(AIAttributionResult(
        evidence_id=evidence.id,
        predicted_source="Human / Camera Original",
        probability=0.05,
        confidence=96.0,
        indicators={},
    ))
    session.commit()

    assessment = TrustService.calculate_score(session, evidence.id)
    trust = TrustAssessmentService.build(session, evidence.id)

    assert assessment["claim_assessment"]["conflict_type"] == "ORIGINAL CLAIM OVER FAKE"
    assert assessment["claim_assessment"]["is_conflict"] is True
    assert assessment["trust_score"] <= 35.0
    assert any("Claim conflict detected" in reason for reason in assessment["reasons"])
    assert trust["claim_assessment"]["conflict_type"] == "ORIGINAL CLAIM OVER FAKE"
