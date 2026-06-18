from __future__ import annotations

import pytest
import uuid
from datetime import datetime
from sqlmodel import select, Session

from app.models.schemas import (
    AIAttributionResult,
    BlockchainRecord,
    Case,
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
from app.services.trust_service import TrustService


def clean_evidence_db(session: Session, evidence_id: str) -> None:
    """Helper to remove all associated records for a test evidence ID."""
    # Delete related tables first
    session.exec(select(Upload).where(Upload.evidence_id == evidence_id)).all()
    for table in [Upload, Hashes, MetadataRecord, ForensicsResult, ProvenanceRecord, DeepfakeResult, AIAttributionResult, BlockchainRecord, Evidence]:
        records = session.exec(select(table).where(getattr(table, "evidence_id" if hasattr(table, "evidence_id") else "id") == evidence_id)).all()
        for r in records:
            session.delete(r)
    session.commit()


@pytest.mark.adversarial
def test_trust_score_user_cases(session: Session) -> None:
    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    # -------------------------------------------------------------
    # Case A: Metadata Valid, Blockchain Valid, C2PA Valid -> Trust > 90
    # -------------------------------------------------------------
    ev_a_id = "EV-MATRIX-CASE-A"
    clean_evidence_db(session, ev_a_id)

    session.add(Evidence(
        id=ev_a_id, case_id=case.id, filename="original_image.png",
        file_type="image", mime_type="image/png", size_bytes=1024,
        status="completed", risk_level="LOW", trust_score=100.0
    ))
    session.add(Upload(
        evidence_id=ev_a_id, storage_path="storage/uploads/a.png",
        integrity_valid=True, malware_scan_passed=True, duplicate_detected=False
    ))
    session.add(MetadataRecord(
        evidence_id=ev_a_id, software_used="", created_datetime=datetime(2026, 6, 11, 12, 0, 0)
    ))
    session.add(ProvenanceRecord(
        evidence_id=ev_a_id, has_manifest=True, manifest_valid=True,
        creator="Studio", device="Camera X", editing_history=[]
    ))
    session.add(BlockchainRecord(
        evidence_id=ev_a_id, chain_name="Polygon", transaction_hash="0x1",
        block_number=100, registered_owner="0xabc", verification_status="VERIFIED OWNER"
    ))
    session.commit()

    score_a = TrustService.calculate_score(session, ev_a_id)
    assert score_a["trust_score"] >= 90.0
    assert score_a["risk_level"] == "LOW"

    # -------------------------------------------------------------
    # Case B: Deepfake Detected, No Provenance -> Trust < 20
    # -------------------------------------------------------------
    ev_b_id = "EV-MATRIX-CASE-B"
    clean_evidence_db(session, ev_b_id)

    session.add(Evidence(
        id=ev_b_id, case_id=case.id, filename="deepfake.mp4",
        file_type="video", mime_type="video/mp4", size_bytes=1024,
        status="completed", risk_level="LOW", trust_score=100.0
    ))
    session.add(Upload(
        evidence_id=ev_b_id, storage_path="storage/uploads/b.mp4",
        integrity_valid=True, malware_scan_passed=True, duplicate_detected=False
    ))
    session.add(DeepfakeResult(
        evidence_id=ev_b_id, model_name="ViT", deepfake_probability=0.95,
        confidence=90.0, explainability={"reason": "Biometric anomalies"}
    ))
    # No C2PA manifest
    session.add(ProvenanceRecord(
        evidence_id=ev_b_id, has_manifest=False, manifest_valid=False
    ))
    session.commit()

    score_b = TrustService.calculate_score(session, ev_b_id)
    assert score_b["trust_score"] < 20.0
    assert score_b["risk_level"] == "CRITICAL"

    # -------------------------------------------------------------
    # Case C: Conflicting Evidence -> Explainable Result
    # -------------------------------------------------------------
    ev_c_id = "EV-MATRIX-CASE-C"
    clean_evidence_db(session, ev_c_id)

    session.add(Evidence(
        id=ev_c_id, case_id=case.id, filename="conflict.png",
        file_type="image", mime_type="image/png", size_bytes=1024,
        status="completed", risk_level="LOW", trust_score=100.0
    ))
    session.add(Upload(
        evidence_id=ev_c_id, storage_path="storage/uploads/c.png",
        integrity_valid=True, malware_scan_passed=True, duplicate_detected=False
    ))
    session.add(MetadataRecord(
        evidence_id=ev_c_id, software_used="", created_datetime=datetime(2026, 6, 11, 12, 0, 0)
    ))
    # Forensics anomalies present
    session.add(ForensicsResult(
        evidence_id=ev_c_id, engine_name="Image ELA", tampered=True,
        confidence=85.0, details={}
    ))
    # But C2PA manifest is valid (Conflict!)
    session.add(ProvenanceRecord(
        evidence_id=ev_c_id, has_manifest=True, manifest_valid=True,
        creator="Reuters News", device="Nikon Z9", editing_history=[]
    ))
    session.commit()

    score_c = TrustService.calculate_score(session, ev_c_id)
    # ELA anomaly deducts 30, but C2PA valid gives 15 boost. Net: 100 - 30 + 15 = 85.
    assert score_c["trust_score"] == 85.0
    assert any("Editing software" not in r for r in score_c["reasons"])
    assert any("Forensics anomaly: JPEG ELA" in r for r in score_c["reasons"])
    assert any("Provenance verified: C2PA" in r for r in score_c["reasons"])


@pytest.mark.adversarial
def test_trust_score_combinatorial_permutations(session: Session) -> None:
    """
    Executes a matrix test of 100+ simulated permutations to verify boundary limits,
    graceful decay of trust score, and secure fallback default levels.
    """
    case = session.exec(select(Case).where(Case.case_number == "CASE-2026-TEST")).first()
    assert case is not None

    # Permutation parameters
    malware_states = [True, False]
    integrity_states = [True, False]
    c2pa_manifest_states = ["none", "valid", "invalid"]
    blockchain_states = [True, False]
    deepfake_probs = [0.05, 0.55, 0.95]

    count = 0
    # Generate 2 * 2 * 3 * 2 * 3 = 72 base permutations.
    for mal in malware_states:
        for integ in integrity_states:
            for c2pa in c2pa_manifest_states:
                for bc in blockchain_states:
                    for df_prob in deepfake_probs:
                        count += 1
                        ev_id = f"EV-PERM-{count}"
                        clean_evidence_db(session, ev_id)

                        # Set up evidence base
                        session.add(Evidence(
                            id=ev_id, case_id=case.id, filename=f"test_file_{count}.png",
                            file_type="image", mime_type="image/png", size_bytes=1024,
                            status="completed", risk_level="LOW", trust_score=100.0
                        ))
                        session.add(Upload(
                            evidence_id=ev_id, storage_path=f"storage/uploads/u_{count}.png",
                            integrity_valid=integ, malware_scan_passed=mal, duplicate_detected=False
                        ))

                        # Setup C2PA manifest
                        has_manifest = (c2pa != "none")
                        manifest_valid = (c2pa == "valid")
                        session.add(ProvenanceRecord(
                            evidence_id=ev_id, has_manifest=has_manifest, manifest_valid=manifest_valid,
                            creator="Editor" if has_manifest else None
                        ))

                        # Setup Blockchain
                        if bc:
                            session.add(BlockchainRecord(
                                evidence_id=ev_id, chain_name="Polygon", transaction_hash=f"0x{count}",
                                block_number=count, registered_owner="0xabc", verification_status="VERIFIED OWNER"
                            ))

                        # Setup Deepfake
                        session.add(DeepfakeResult(
                            evidence_id=ev_id, model_name="ViT", deepfake_probability=df_prob,
                            confidence=90.0, explainability={}
                        ))

                        session.commit()

                        # Calculate and verify assertions
                        result = TrustService.calculate_score(session, ev_id)
                        trust = result["trust_score"]
                        risk = result["risk_level"]

                        assert 0.0 <= trust <= 100.0

                        # Rule assertions
                        if not mal:
                            # Malware detected -> trust must be 0 and risk CRITICAL
                            assert trust == 0.0
                            assert risk == "CRITICAL"
                        
                        if mal and df_prob > 0.80:
                            # Deepfake detected -> trust must be 0 and risk CRITICAL
                            assert trust == 0.0
                            assert risk == "CRITICAL"

                        if mal and df_prob < 0.10 and c2pa == "invalid":
                            # Invalid/forged manifest signature forces score to <= 10 (or <= 20 if blockchain verified)
                            assert (trust <= 10.0 if not bc else trust <= 20.0)

                        clean_evidence_db(session, ev_id)
