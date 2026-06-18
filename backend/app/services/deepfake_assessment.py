from __future__ import annotations

from typing import Any, Dict, List, Optional


class DeepfakeAssessmentService:
    @staticmethod
    def build(file_type: str, result: Dict[str, Any]) -> Dict[str, Any]:
        probability = float(result.get("deepfake_probability", 0.0) or 0.0)
        confidence = float(result.get("confidence", 0.0) or 0.0)
        model_name = result.get("model_name", "Unknown Model")
        explainability = result.get("explainability", {}) or {}
        heatmap_path = result.get("heatmap_path")
        tampered = bool(result.get("tampered", probability >= 0.45))

        risk_level = DeepfakeAssessmentService._risk_level(probability)
        supporting_evidence = DeepfakeAssessmentService._evidence_from_explainability(file_type, explainability)
        if heatmap_path:
            supporting_evidence.append("Heatmap overlay generated for visual explainability.")
        if not supporting_evidence:
            supporting_evidence.append("No deepfake-specific anomalies were detected.")

        return {
            "file_type": file_type,
            "model_name": model_name,
            "deepfake_probability": round(probability, 2),
            "confidence_score": round(confidence, 2),
            "risk_level": risk_level,
            "tampered": tampered,
            "verification_method": DeepfakeAssessmentService._verification_method(file_type),
            "supporting_evidence": supporting_evidence,
            "heatmap_available": bool(heatmap_path),
            "heatmap_path": heatmap_path,
            "explainability": DeepfakeAssessmentService._compact_explainability(explainability),
        }

    @staticmethod
    def build_from_record(file_type: str, record: Any) -> Dict[str, Any]:
        if not record:
            return DeepfakeAssessmentService.build(file_type, {})

        return DeepfakeAssessmentService.build(
            file_type,
            {
                "model_name": getattr(record, "model_name", "Unknown Model"),
                "deepfake_probability": getattr(record, "deepfake_probability", 0.0),
                "confidence": getattr(record, "confidence", 0.0),
                "heatmap_path": getattr(record, "heatmap_path", None),
                "explainability": getattr(record, "explainability", {}) or {},
                "tampered": float(getattr(record, "deepfake_probability", 0.0) or 0.0) >= 0.45,
            },
        )

    @staticmethod
    def _risk_level(probability: float) -> str:
        if probability >= 0.80:
            return "CRITICAL"
        if probability >= 0.45:
            return "HIGH"
        if probability >= 0.20:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _verification_method(file_type: str) -> str:
        if file_type == "image":
            return "DeepFakeBench image model ensemble + heatmap explainability"
        if file_type == "video":
            return "Temporal consistency analysis + frame boundary inspection"
        if file_type == "audio":
            return "Voice cloning spectrogram analysis + harmonic deviation scoring"
        return "Heuristic deepfake risk assessment"

    @staticmethod
    def _evidence_from_explainability(file_type: str, explainability: Dict[str, Any]) -> List[str]:
        evidence: List[str] = []

        if file_type == "image":
            if explainability.get("eyebrow_asymmetry_ratio") is not None:
                evidence.append(
                    f"Eyebrow asymmetry ratio: {explainability['eyebrow_asymmetry_ratio']}."
                )
            if explainability.get("noise_discontinuity_score") is not None:
                evidence.append(
                    f"Noise discontinuity score: {explainability['noise_discontinuity_score']}."
                )
            if explainability.get("spliced_regions"):
                evidence.append(
                    f"Flagged regions: {', '.join(str(item) for item in explainability['spliced_regions'])}."
                )
            if explainability.get("target_dataset_matches"):
                evidence.append(
                    f"Model aligned with datasets: {', '.join(str(item) for item in explainability['target_dataset_matches'])}."
                )

        elif file_type == "video":
            if explainability.get("temporal_jitter_score") is not None:
                evidence.append(
                    f"Temporal jitter score: {explainability['temporal_jitter_score']}."
                )
            if explainability.get("lip_sync_lag_ms") is not None:
                evidence.append(
                    f"Lip-sync lag: {explainability['lip_sync_lag_ms']} ms."
                )
            if explainability.get("manipulated_frames_range"):
                evidence.append(
                    f"Manipulated frames range: {explainability['manipulated_frames_range']}."
                )
            if explainability.get("spliced_regions"):
                evidence.append(
                    f"Flagged regions: {', '.join(str(item) for item in explainability['spliced_regions'])}."
                )

        elif file_type == "audio":
            if explainability.get("synthetic_robotics_index") is not None:
                evidence.append(
                    f"Synthetic robotics index: {explainability['synthetic_robotics_index']}."
                )
            if explainability.get("harmonic_peaks_deviation") is not None:
                evidence.append(
                    f"Harmonic peaks deviation: {explainability['harmonic_peaks_deviation']}."
                )

        return evidence

    @staticmethod
    def _compact_explainability(explainability: Dict[str, Any]) -> Dict[str, Any]:
        compact = {}
        for key in (
            "facial_bounding_box",
            "eyebrow_asymmetry_ratio",
            "noise_discontinuity_score",
            "target_dataset_matches",
            "spliced_regions",
            "temporal_jitter_score",
            "lip_sync_lag_ms",
            "manipulated_frames_range",
            "synthetic_robotics_index",
            "harmonic_peaks_deviation",
        ):
            if key in explainability:
                compact[key] = explainability[key]
        return compact
