from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlmodel import Session, select

from app.models.schemas import (
    AIAttributionResult,
    BlockchainRecord,
    DeepfakeResult,
    Evidence,
    ForensicsResult,
    Hashes,
    MetadataRecord,
    ProvenanceRecord,
    Upload,
)
from app.services.blockchain_assessment import BlockchainAssessmentService
from app.services.claim_consistency_service import ClaimConsistencyService
from app.services.deepfake_assessment import DeepfakeAssessmentService
from app.services.forensics_summary import ForensicsSummaryService
from app.services.provenance_service import ProvenanceService


class TrustAssessmentService:
    @staticmethod
    def build(db: Session, evidence_id: str) -> Dict[str, Any]:
        evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
        if not evidence:
            return {
                "trust_score": 0.0,
                "risk_level": "CRITICAL",
                "confidence_score": 0.0,
                "verdict": "UNKNOWN",
                "trust_band": "UNAVAILABLE",
                "stability": "UNAVAILABLE",
                "reasons": ["Evidence not found."],
                "supporting_evidence": ["Evidence not found."],
                "recommendations": ["Verify the evidence identifier and retry."],
                "verification_methods": [],
                "component_breakdown": {},
            }

        upload = db.exec(select(Upload).where(Upload.evidence_id == evidence_id)).first()
        hashes = db.exec(select(Hashes).where(Hashes.evidence_id == evidence_id)).first()
        metadata = db.exec(select(MetadataRecord).where(MetadataRecord.evidence_id == evidence_id)).first()
        forensics = db.exec(select(ForensicsResult).where(ForensicsResult.evidence_id == evidence_id)).all()
        provenance = db.exec(select(ProvenanceRecord).where(ProvenanceRecord.evidence_id == evidence_id)).first()
        deepfake = db.exec(select(DeepfakeResult).where(DeepfakeResult.evidence_id == evidence_id)).first()
        ai_attr = db.exec(select(AIAttributionResult).where(AIAttributionResult.evidence_id == evidence_id)).first()
        blockchain = db.exec(select(BlockchainRecord).where(BlockchainRecord.evidence_id == evidence_id)).first()

        forensics_summary = ForensicsSummaryService.build_from_records(evidence.file_type, forensics)
        deepfake_assessment = DeepfakeAssessmentService.build_from_record(evidence.file_type, deepfake)
        provenance_assessment = None
        if provenance and upload:
            provenance_assessment = ProvenanceService.assess_provenance(
                upload.storage_path,
                metadata={
                    "creator": provenance.creator,
                    "device": provenance.device,
                    "editing_history": provenance.editing_history,
                    "software_used": metadata.software_used if metadata else None,
                },
                blockchain_verified=bool(blockchain),
            )
        blockchain_assessment = BlockchainAssessmentService.build(
            blockchain,
            evidence_hash=hashes.sha256 if hashes else None,
            provenance_assessment=provenance_assessment,
            trust_score=evidence.trust_score,
        )
        claim_assessment = ClaimConsistencyService.assess(
            filename=evidence.filename,
            file_type=evidence.file_type,
            metadata={
                "creator": metadata.creator if metadata else None,
                "software_used": metadata.software_used if metadata else None,
                "device": provenance.device if provenance else None,
            },
            raw_metadata=metadata.raw_metadata if metadata else {},
            upload=upload,
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment or {},
            deepfake_assessment=deepfake_assessment,
            ai_attribution=ai_attr,
            blockchain_assessment=blockchain_assessment,
        )

        raw_score = float(evidence.trust_score or 0.0)
        risk_level = TrustAssessmentService._risk_from_score(raw_score)
        confidence_score = TrustAssessmentService._confidence_from_components(
            upload=upload,
            metadata=metadata,
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment,
            deepfake_assessment=deepfake_assessment,
            blockchain_assessment=blockchain_assessment,
            ai_attr=ai_attr,
            claim_assessment=claim_assessment,
        )
        component_breakdown = TrustAssessmentService._component_breakdown(
            upload=upload,
            metadata=metadata,
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment,
            deepfake_assessment=deepfake_assessment,
            blockchain_assessment=blockchain_assessment,
            ai_attr=ai_attr,
            claim_assessment=claim_assessment,
            raw_score=raw_score,
        )
        supporting_evidence = TrustAssessmentService._supporting_evidence(
            component_breakdown,
            forensics_summary,
            provenance_assessment,
            deepfake_assessment,
            blockchain_assessment,
            claim_assessment,
        )
        reasons = TrustAssessmentService._reasons(
            raw_score=raw_score,
            risk_level=risk_level,
            upload=upload,
            metadata=metadata,
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment,
            deepfake_assessment=deepfake_assessment,
            blockchain_assessment=blockchain_assessment,
            ai_attr=ai_attr,
            claim_assessment=claim_assessment,
        )
        verification_methods = TrustAssessmentService._verification_methods(
            upload=upload,
            metadata=metadata,
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment,
            deepfake_assessment=deepfake_assessment,
            blockchain_assessment=blockchain_assessment,
            ai_attr=ai_attr,
            claim_assessment=claim_assessment,
        )
        recommendations = TrustAssessmentService._recommendations(
            risk_level=risk_level,
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment,
            deepfake_assessment=deepfake_assessment,
            blockchain_assessment=blockchain_assessment,
            claim_assessment=claim_assessment,
        )

        verdict = "HIGH TRUST" if raw_score >= 85 else "MODERATE TRUST" if raw_score >= 50 else "LOW TRUST"
        trust_band = "GREEN" if raw_score >= 85 else "AMBER" if raw_score >= 50 else "ORANGE" if raw_score >= 20 else "RED"
        if risk_level == "CRITICAL":
            stability = "UNSTABLE"
        elif risk_level == "HIGH":
            stability = "DEGRADED"
        elif risk_level == "MEDIUM":
            stability = "WATCH"
        else:
            stability = "STABLE"

        return {
            "evidence_id": evidence_id,
            "trust_score": round(raw_score, 2),
            "risk_level": risk_level,
            "confidence_score": round(confidence_score, 2),
            "verdict": verdict,
            "trust_band": trust_band,
            "stability": stability,
            "reasons": reasons,
            "supporting_evidence": supporting_evidence,
            "recommendations": recommendations,
            "verification_methods": verification_methods,
            "component_breakdown": component_breakdown,
            "forensics_summary": forensics_summary,
            "provenance_assessment": provenance_assessment,
            "deepfake_assessment": deepfake_assessment,
            "blockchain_assessment": blockchain_assessment,
            "claim_assessment": claim_assessment,
            "evidence_status": evidence.status,
            "evidence_risk_level": evidence.risk_level,
        }

    @staticmethod
    def _risk_from_score(score: float) -> str:
        if score >= 85:
            return "LOW"
        if score >= 50:
            return "MEDIUM"
        if score >= 20:
            return "HIGH"
        return "CRITICAL"

    @staticmethod
    def _confidence_from_components(
        *,
        upload: Optional[Upload],
        metadata: Optional[MetadataRecord],
        forensics_summary: Dict[str, Any],
        provenance_assessment: Optional[Dict[str, Any]],
        deepfake_assessment: Dict[str, Any],
        blockchain_assessment: Dict[str, Any],
        ai_attr: Optional[AIAttributionResult],
        claim_assessment: Optional[Dict[str, Any]] = None,
    ) -> float:
        score = 50.0
        if upload and upload.integrity_valid:
            score += 8.0
        if metadata:
            score += 6.0
        if forensics_summary.get("supporting_evidence"):
            score += min(10.0, len(forensics_summary["supporting_evidence"]) * 1.5)
        if provenance_assessment:
            score += 12.0 if provenance_assessment.get("ownership_classification") == "VERIFIED OWNER" else 6.0
        if deepfake_assessment.get("heatmap_available"):
            score += 8.0
        if blockchain_assessment.get("anchored"):
            score += 10.0
        if claim_assessment and claim_assessment.get("is_conflict"):
            score -= 10.0 if claim_assessment.get("severity") in {"MEDIUM"} else 14.0
        if ai_attr and ai_attr.predicted_source != "Human / Camera Original":
            score += 4.0
        return max(0.0, min(100.0, score))

    @staticmethod
    def _component_breakdown(
        *,
        upload: Optional[Upload],
        metadata: Optional[MetadataRecord],
        forensics_summary: Dict[str, Any],
        provenance_assessment: Optional[Dict[str, Any]],
        deepfake_assessment: Dict[str, Any],
        blockchain_assessment: Dict[str, Any],
        ai_attr: Optional[AIAttributionResult],
        raw_score: float,
        claim_assessment: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "integrity": {
                "state": "valid" if upload and upload.integrity_valid else "invalid",
                "weight": 8 if upload and upload.integrity_valid else -20,
            },
            "metadata": {
                "state": "present" if metadata else "missing",
                "weight": 6 if metadata else -10,
            },
            "forensics": {
                "state": "tampered" if forensics_summary.get("tampered") else "clean",
                "weight": -sum(1 for item in forensics_summary.get("supporting_evidence", []) if item),
            },
            "provenance": {
                "state": (provenance_assessment or {}).get("ownership_classification", "UNKNOWN OWNER"),
                "weight": 12 if (provenance_assessment or {}).get("ownership_classification") == "VERIFIED OWNER" else 4 if provenance_assessment else 0,
            },
            "deepfake": {
                "state": deepfake_assessment.get("risk_level", "LOW"),
                "weight": -15 if deepfake_assessment.get("risk_level") in {"HIGH", "CRITICAL"} else -5 if deepfake_assessment.get("risk_level") == "MEDIUM" else 0,
            },
            "blockchain": {
                "state": "anchored" if blockchain_assessment.get("anchored") else "unanchored",
                "weight": 10 if blockchain_assessment.get("anchored") else 0,
            },
            "ai_attribution": {
                "state": ai_attr.predicted_source if ai_attr else "unavailable",
                "weight": -8 if ai_attr and ai_attr.predicted_source != "Human / Camera Original" else 0,
            },
            "claim_consistency": {
                "state": (claim_assessment or {}).get("conflict_type", "consistent"),
                "weight": -12 if (claim_assessment or {}).get("is_conflict") else 0,
            },
            "raw_score": round(raw_score, 2),
        }

    @staticmethod
    def _supporting_evidence(
        component_breakdown: Dict[str, Any],
        forensics_summary: Dict[str, Any],
        provenance_assessment: Optional[Dict[str, Any]],
        deepfake_assessment: Dict[str, Any],
        blockchain_assessment: Dict[str, Any],
        claim_assessment: Optional[Dict[str, Any]],
    ) -> List[str]:
        evidence: List[str] = []
        if forensics_summary.get("supporting_evidence"):
            evidence.extend(forensics_summary["supporting_evidence"][:4])
        if provenance_assessment:
            evidence.extend(provenance_assessment.get("supporting_evidence", [])[:4])
        if deepfake_assessment:
            evidence.extend(deepfake_assessment.get("supporting_evidence", [])[:4])
        if blockchain_assessment:
            evidence.extend(blockchain_assessment.get("supporting_evidence", [])[:4])
        if claim_assessment:
            evidence.extend(claim_assessment.get("supporting_evidence", [])[:4])
        if not evidence:
            evidence.append("No strong trust signals detected.")
        return evidence[:10]

    @staticmethod
    def _reasons(
        *,
        raw_score: float,
        risk_level: str,
        upload: Optional[Upload],
        metadata: Optional[MetadataRecord],
        forensics_summary: Dict[str, Any],
        provenance_assessment: Optional[Dict[str, Any]],
        deepfake_assessment: Dict[str, Any],
        blockchain_assessment: Dict[str, Any],
        ai_attr: Optional[AIAttributionResult],
        claim_assessment: Optional[Dict[str, Any]],
    ) -> List[str]:
        reasons: List[str] = [
            f"Raw trust score resolved to {raw_score:.1f}%.",
            f"Risk band classified as {risk_level}.",
        ]

        if upload and upload.integrity_valid:
            reasons.append("Binary integrity verification passed.")
        elif upload:
            reasons.append("Binary integrity verification failed.")

        if metadata:
            reasons.append("Structural metadata was extracted successfully.")
        else:
            reasons.append("Structural metadata was not available for this evidence.")

        if forensics_summary.get("tampered"):
            reasons.append("Forensic analysis found tamper indicators.")
        elif forensics_summary.get("supporting_evidence"):
            reasons.append("Forensic analysis produced corroborating evidence.")

        if provenance_assessment:
            reasons.append(
                f"Provenance resolved to {provenance_assessment.get('ownership_classification', 'UNKNOWN OWNER')}."
            )
        if deepfake_assessment.get("risk_level") in {"HIGH", "CRITICAL"}:
            reasons.append(
                f"Deepfake detected: {float(deepfake_assessment.get('deepfake_probability', 0.0) or 0.0) * 100:.1f}% probability."
            )
            reasons.append("Deepfake indicators are elevated and require review.")
        if blockchain_assessment.get("anchored"):
            reasons.append("Ledger anchoring strengthens custody continuity.")
        if ai_attr and ai_attr.predicted_source != "Human / Camera Original":
            reasons.append(f"AI attribution flagged a synthetic source: {ai_attr.predicted_source}.")
        if claim_assessment and claim_assessment.get("is_conflict"):
            reasons.append(
                f"Claim conflict detected: {claim_assessment['conflict_type']} ({claim_assessment['severity']})."
            )
            reasons.append(
                f"Claim label: {claim_assessment.get('claim_label', 'UNSPECIFIED')} vs content label: {claim_assessment.get('content_label', 'INCONCLUSIVE')}."
            )

        return reasons[:10]

    @staticmethod
    def _verification_methods(
        *,
        upload: Optional[Upload],
        metadata: Optional[MetadataRecord],
        forensics_summary: Dict[str, Any],
        provenance_assessment: Optional[Dict[str, Any]],
        deepfake_assessment: Dict[str, Any],
        blockchain_assessment: Dict[str, Any],
        ai_attr: Optional[AIAttributionResult],
        claim_assessment: Optional[Dict[str, Any]],
    ) -> List[str]:
        methods: List[str] = ["Cryptographic Hash Digest"]
        if upload and upload.integrity_valid:
            methods.append("Binary Magic Bytes Ingestion Signature")
        if metadata:
            methods.append("Metadata Structure Properties extraction")
        if forensics_summary.get("supporting_evidence"):
            methods.append("Deep Forensic Spectral & Noise Audits")
        if provenance_assessment:
            methods.append("C2PA Content Credentials Manifest Chain")
        if deepfake_assessment.get("supporting_evidence"):
            methods.append("Deepfake Biometric Distortion Scanning")
        if ai_attr:
            methods.append("Generative Model Attribution Signature Checking")
        if blockchain_assessment.get("anchored"):
            methods.append("Blockchain Public Ledger Anchor Custody")
        if claim_assessment:
            methods.append("Claim-vs-Content Consistency Review")
        return methods

    @staticmethod
    def _recommendations(
        *,
        risk_level: str,
        forensics_summary: Dict[str, Any],
        provenance_assessment: Optional[Dict[str, Any]],
        deepfake_assessment: Dict[str, Any],
        blockchain_assessment: Dict[str, Any],
        claim_assessment: Optional[Dict[str, Any]],
    ) -> List[str]:
        recommendations: List[str] = []
        if risk_level == "CRITICAL":
            recommendations.append("Treat the evidence as operationally unsafe until independently corroborated.")
        elif risk_level == "HIGH":
            recommendations.append("Require secondary verification before sharing outside the case team.")
        else:
            recommendations.append("Trust signal is acceptable but should still be corroborated against source context.")

        if forensics_summary.get("tampered"):
            recommendations.append("Review the forensic artifacts for localized manipulation indicators.")
        if provenance_assessment and provenance_assessment.get("ownership_classification") != "VERIFIED OWNER":
            recommendations.append("Do not assert ownership certainty without cryptographic or blockchain proof.")
        if deepfake_assessment.get("risk_level") in {"HIGH", "CRITICAL"}:
            recommendations.append("Escalate to media verification or biometric review.")
        if blockchain_assessment.get("anchored") and blockchain_assessment.get("anchor_strength", 0) >= 95:
            recommendations.append("Ledger anchoring is strong and can support chain-of-custody attestations.")
        if claim_assessment and claim_assessment.get("is_conflict"):
            recommendations.append("Resolve the claim-content conflict before asserting originality or authorship.")
        return recommendations[:6]
