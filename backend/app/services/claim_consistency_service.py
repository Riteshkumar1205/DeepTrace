from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


class ClaimConsistencyService:
    ORIGINAL_TOKENS = (
        "original",
        "authentic",
        "verified",
        "real",
        "unedited",
        "raw",
        "master",
        "source",
        "camera original",
        "human original",
    )
    SYNTHETIC_TOKENS = (
        "fake",
        "forged",
        "clone",
        "deepfake",
        "synthetic",
        "generated",
        "ai",
        "midjourney",
        "stable diffusion",
        "sdxl",
        "flux",
        "dall-e",
        "dalle",
        "sora",
        "runway",
        "edited",
        "altered",
        "tampered",
        "manipulated",
    )

    @staticmethod
    def assess(
        *,
        filename: str,
        file_type: str,
        metadata: Optional[Dict[str, Any]] = None,
        raw_metadata: Optional[Dict[str, Any]] = None,
        upload: Optional[Any] = None,
        forensics_summary: Optional[Dict[str, Any]] = None,
        provenance_assessment: Optional[Dict[str, Any]] = None,
        deepfake_assessment: Optional[Dict[str, Any]] = None,
        ai_attribution: Optional[Any] = None,
        blockchain_assessment: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        metadata = metadata or {}
        raw_metadata = raw_metadata or {}
        forensics_summary = forensics_summary or {}
        provenance_assessment = provenance_assessment or {}
        deepfake_assessment = deepfake_assessment or {}
        blockchain_assessment = blockchain_assessment or {}

        claim_terms = ClaimConsistencyService._collect_text_claims(
            filename=filename,
            metadata=metadata,
            raw_metadata=raw_metadata,
        )
        claim_label, claim_confidence, claim_evidence = ClaimConsistencyService._infer_claim(claim_terms)
        content_label, content_confidence, content_evidence = ClaimConsistencyService._infer_content(
            file_type=file_type,
            upload=upload,
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment,
            deepfake_assessment=deepfake_assessment,
            ai_attribution=ai_attribution,
            blockchain_assessment=blockchain_assessment,
        )

        conflict_type = None
        if claim_label == "ORIGINAL" and content_label == "SYNTHETIC":
            conflict_type = "FAKE CLAIM OVER ORIGINAL"
        elif claim_label == "SYNTHETIC" and content_label == "ORIGINAL":
            conflict_type = "ORIGINAL CLAIM OVER FAKE"

        conflict_confidence = min(100.0, max(claim_confidence, content_confidence))
        severity = ClaimConsistencyService._severity_from_signal(
            conflict_type=conflict_type,
            claim_confidence=claim_confidence,
            content_confidence=content_confidence,
            claim_label=claim_label,
            content_label=content_label,
        )

        supporting_evidence: List[str] = []
        supporting_evidence.extend(claim_evidence)
        supporting_evidence.extend(content_evidence)
        if conflict_type:
            supporting_evidence.append(f"Conflict resolved as {conflict_type.lower()}.")
        if not supporting_evidence:
            supporting_evidence.append("No claim-vs-content conflict indicators were detected.")

        recommendations = ClaimConsistencyService._recommendations(
            conflict_type=conflict_type,
            severity=severity,
            content_label=content_label,
            provenance_assessment=provenance_assessment,
            deepfake_assessment=deepfake_assessment,
        )

        return {
            "claim_label": claim_label,
            "claim_confidence": round(claim_confidence, 2),
            "claim_terms": claim_terms,
            "content_label": content_label,
            "content_confidence": round(content_confidence, 2),
            "conflict_type": conflict_type,
            "conflict_confidence": round(conflict_confidence, 2),
            "severity": severity,
            "supporting_evidence": supporting_evidence,
            "recommendations": recommendations,
            "is_conflict": conflict_type is not None,
        }

    @staticmethod
    def _collect_text_claims(
        *,
        filename: str,
        metadata: Dict[str, Any],
        raw_metadata: Dict[str, Any],
    ) -> List[str]:
        values: List[str] = [filename]
        for key in ("creator", "device", "title", "description"):
            value = metadata.get(key)
            if value:
                values.append(str(value))

        return values

    @staticmethod
    def _infer_claim(terms: Sequence[str]) -> Tuple[str, float, List[str]]:
        original_hits: List[str] = []
        synthetic_hits: List[str] = []

        normalized_terms = [term.lower() for term in terms if term]
        for term in normalized_terms:
            for token in ClaimConsistencyService.ORIGINAL_TOKENS:
                if token in term:
                    original_hits.append(f"Claim/origin cue: '{token}' in '{term}'.")
                    break
            for token in ClaimConsistencyService.SYNTHETIC_TOKENS:
                if token in term:
                    synthetic_hits.append(f"Claim/synthetic cue: '{token}' in '{term}'.")
                    break

        original_score = len(original_hits)
        synthetic_score = len(synthetic_hits)

        if original_score == 0 and synthetic_score == 0:
            return "UNSPECIFIED", 0.0, ["No explicit originality claim markers were detected."]

        if original_score > synthetic_score:
            confidence = 45.0 + min(45.0, original_score * 12.0)
            return "ORIGINAL", confidence, original_hits[:4]

        if synthetic_score > original_score:
            confidence = 45.0 + min(45.0, synthetic_score * 12.0)
            return "SYNTHETIC", confidence, synthetic_hits[:4]

        confidence = 40.0 + min(30.0, max(original_score, synthetic_score) * 10.0)
        evidence = (original_hits + synthetic_hits)[:4]
        return "AMBIGUOUS", confidence, evidence

    @staticmethod
    def _infer_content(
        *,
        file_type: str,
        upload: Optional[Any],
        forensics_summary: Dict[str, Any],
        provenance_assessment: Dict[str, Any],
        deepfake_assessment: Dict[str, Any],
        ai_attribution: Optional[Any],
        blockchain_assessment: Dict[str, Any],
    ) -> Tuple[str, float, List[str]]:
        original_score = 0.0
        synthetic_score = 0.0
        evidence: List[str] = []

        if upload and getattr(upload, "integrity_valid", False):
            original_score += 2.0
            evidence.append("Upload integrity checks passed.")
        elif upload:
            synthetic_score += 2.0
            evidence.append("Upload integrity checks failed.")

        if not forensics_summary.get("tampered"):
            original_score += 2.0
            evidence.append("Forensics summary is clean.")
        else:
            synthetic_score += 3.0
            evidence.append("Forensics summary reports tampering.")

        provenance_state = provenance_assessment.get("ownership_classification")
        if provenance_assessment.get("manifest_valid"):
            original_score += 3.0
            evidence.append("C2PA provenance manifest validated.")
        elif provenance_assessment.get("has_manifest"):
            synthetic_score += 1.5
            evidence.append("C2PA manifest present but invalid.")
        else:
            synthetic_score += 1.0
            evidence.append("No valid provenance manifest detected.")

        if provenance_state == "VERIFIED OWNER":
            original_score += 1.5
        elif provenance_state == "PROBABLE OWNER":
            original_score += 0.5

        deepfake_probability = float(deepfake_assessment.get("deepfake_probability", 0.0) or 0.0)
        deepfake_risk = deepfake_assessment.get("risk_level", "LOW")
        if deepfake_probability >= 0.8 or deepfake_risk == "CRITICAL":
            synthetic_score += 4.0
            evidence.append("Deepfake assessment is critical.")
        elif deepfake_probability >= 0.45 or deepfake_risk == "HIGH":
            synthetic_score += 2.5
            evidence.append("Deepfake assessment is elevated.")
        else:
            original_score += 1.5
            evidence.append("Deepfake assessment is low risk.")

        if ai_attribution:
            predicted_source = str(getattr(ai_attribution, "predicted_source", "") or "")
            if predicted_source in {"Human / Camera Original", "Human/Unknown"}:
                original_score += 2.0
                evidence.append(f"AI attribution aligned to human/original source: {predicted_source}.")
            else:
                synthetic_score += 2.5
                evidence.append(f"AI attribution flagged a synthetic source: {predicted_source}.")

        if blockchain_assessment.get("anchored"):
            original_score += 1.5
            evidence.append("Blockchain custody is anchored.")
        elif blockchain_assessment:
            synthetic_score += 0.5

        if file_type in {"image", "video", "audio", "document"}:
            evidence.append(f"Content evaluated for {file_type} evidence semantics.")

        if original_score >= synthetic_score + 2.0 and original_score >= 4.0:
            confidence = min(100.0, 55.0 + original_score * 7.0)
            return "ORIGINAL", confidence, evidence[:6]

        if synthetic_score >= original_score + 2.0 and synthetic_score >= 4.0:
            confidence = min(100.0, 55.0 + synthetic_score * 7.0)
            return "SYNTHETIC", confidence, evidence[:6]

        confidence = min(100.0, 40.0 + max(original_score, synthetic_score) * 6.0)
        return "INCONCLUSIVE", confidence, evidence[:6]

    @staticmethod
    def _severity_from_signal(
        *,
        conflict_type: Optional[str],
        claim_confidence: float,
        content_confidence: float,
        claim_label: str,
        content_label: str,
    ) -> str:
        if not conflict_type:
            return "LOW"

        if claim_confidence >= 85.0 and content_confidence >= 85.0:
            return "CRITICAL"
        if claim_confidence >= 70.0 and content_confidence >= 70.0:
            return "HIGH"
        if claim_label == "AMBIGUOUS" or content_label == "INCONCLUSIVE":
            return "MEDIUM"
        return "HIGH"

    @staticmethod
    def _recommendations(
        *,
        conflict_type: Optional[str],
        severity: str,
        content_label: str,
        provenance_assessment: Dict[str, Any],
        deepfake_assessment: Dict[str, Any],
    ) -> List[str]:
        recommendations: List[str] = []
        if conflict_type:
            recommendations.append(f"Treat the asset as {conflict_type.lower()} until independently corroborated.")
        else:
            recommendations.append("No direct claim conflict detected, but continue normal corroboration.")

        if severity in {"HIGH", "CRITICAL"}:
            recommendations.append("Escalate to chain-of-custody and source verification review.")
        if content_label == "SYNTHETIC":
            recommendations.append("Mark the evidence as non-original or synthetic in the case notes.")
        if provenance_assessment.get("ownership_classification") != "VERIFIED OWNER":
            recommendations.append("Do not state ownership certainty without verified provenance.")
        if deepfake_assessment.get("risk_level") in {"HIGH", "CRITICAL"}:
            recommendations.append("Review the media for manipulation artifacts and regenerate the hash chain.")
        return recommendations[:5]
