from __future__ import annotations

from typing import Any, Dict, Optional


class BlockchainAssessmentService:
    @staticmethod
    def build(
        record: Optional[Any],
        *,
        evidence_hash: Optional[str] = None,
        provenance_assessment: Optional[Dict[str, Any]] = None,
        trust_score: Optional[float] = None,
    ) -> Dict[str, Any]:
        if not record:
            return {
                "anchored": False,
                "verification_status": "UNREGISTERED",
                "ownership_classification": "UNKNOWN OWNER",
                "confidence_score": 0.0,
                "anchor_strength": 0.0,
                "verification_method": "Ledger lookup",
                "supporting_evidence": ["No blockchain record found for this evidence item."],
                "transaction_hash": None,
                "block_number": None,
                "registered_owner": None,
                "chain_name": None,
            }

        supporting_evidence = [
            f"Evidence anchored on {record.chain_name} at block {record.block_number}.",
            "Transaction receipt present in the simulated ledger.",
        ]

        if evidence_hash:
            supporting_evidence.append(f"Anchored SHA-256 evidence digest: {evidence_hash}.")

        provenance_status = (provenance_assessment or {}).get("ownership_classification") or (
            provenance_assessment or {}
        ).get("verification_status")

        ownership_classification = "VERIFIED OWNER"
        if provenance_status == "PROBABLE OWNER" or (trust_score is not None and trust_score < 50):
            ownership_classification = "PROBABLE OWNER"

        confidence_score = 90.0
        if provenance_status == "VERIFIED OWNER":
            confidence_score += 5.0
        if trust_score is not None and trust_score >= 80:
            confidence_score += 2.5
        if trust_score is not None and trust_score < 50:
            confidence_score -= 15.0

        anchor_strength = 95.0
        if evidence_hash:
            anchor_strength += 2.5
        if trust_score is not None and trust_score >= 80:
            anchor_strength += 2.5
        if provenance_status == "PROBABLE OWNER":
            anchor_strength -= 5.0

        confidence_score = max(0.0, min(100.0, confidence_score))
        anchor_strength = max(0.0, min(100.0, anchor_strength))

        return {
            "anchored": True,
            "verification_status": record.verification_status,
            "ownership_classification": ownership_classification,
            "confidence_score": round(confidence_score, 2),
            "anchor_strength": round(anchor_strength, 2),
            "verification_method": "Ledger anchor + hash continuity + custody audit",
            "supporting_evidence": supporting_evidence,
            "transaction_hash": record.transaction_hash,
            "block_number": record.block_number,
            "registered_owner": record.registered_owner,
            "chain_name": record.chain_name,
            "timestamp": record.created_at.isoformat() if record.created_at else None,
        }
