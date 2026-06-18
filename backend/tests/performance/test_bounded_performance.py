from __future__ import annotations

import time
from pathlib import Path

import pytest
from sqlmodel import select

from app.models.schemas import AIAttributionResult, BlockchainRecord, DeepfakeResult, Evidence, Hashes, MetadataRecord, Organization, ProvenanceRecord, Upload, User, Case
from app.services.hashing_service import HashingService
from app.services.trust_assessment import TrustAssessmentService


@pytest.mark.performance
def test_crypto_hashing_stays_within_bounded_latency(tmp_path: Path) -> None:
    target = tmp_path / "large.bin"
    target.write_bytes(b"A" * (1024 * 1024))

    start = time.perf_counter()
    hashes = HashingService.calculate_crypto_hashes(str(target))
    elapsed = time.perf_counter() - start

    assert len(hashes[1]) == 64
    assert elapsed < 1.5


@pytest.mark.performance
def test_trust_assessment_build_stays_quick(session) -> None:
    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    evidence = Evidence(
        id="EV-PERF-1",
        case_id=case.id,
        filename="performance.png",
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
        storage_path="storage/uploads/performance.png",
        integrity_valid=True,
        malware_scan_passed=True,
        duplicate_detected=False,
    ))
    session.add(Hashes(
        evidence_id=evidence.id,
        md5="m",
        sha256="s",
        sha512="x",
    ))
    session.add(MetadataRecord(evidence_id=evidence.id, raw_metadata={}))
    session.add(DeepfakeResult(evidence_id=evidence.id, model_name="ViT", deepfake_probability=0.05, confidence=93.0, explainability={}))
    session.add(AIAttributionResult(evidence_id=evidence.id, predicted_source="Human / Camera Original", probability=0.05, confidence=80.0, indicators={}))
    session.add(ProvenanceRecord(evidence_id=evidence.id, has_manifest=True, manifest_valid=True, creator="Studio", device="Camera", editing_history=[]))
    session.add(BlockchainRecord(
        evidence_id=evidence.id,
        chain_name="Polygon PoS (Mainnet Anchor)",
        transaction_hash="0xabc",
        block_number=45890001,
        registered_owner="0xdef",
        verification_status="VERIFIED OWNER",
    ))
    session.commit()

    start = time.perf_counter()
    result = TrustAssessmentService.build(session, evidence.id)
    elapsed = time.perf_counter() - start

    assert result["evidence_id"] == evidence.id
    assert elapsed < 1.0
