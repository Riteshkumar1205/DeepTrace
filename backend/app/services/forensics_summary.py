from __future__ import annotations

from typing import Any, Dict, List, Optional


class ForensicsSummaryService:
    @staticmethod
    def build_from_service_result(file_type: str, result: Dict[str, Any]) -> Dict[str, Any]:
        if file_type == "image":
            return ForensicsSummaryService._build_image_summary(result)
        if file_type == "video":
            return ForensicsSummaryService._build_video_summary(result)
        if file_type == "audio":
            return ForensicsSummaryService._build_audio_summary(result)
        if file_type == "document":
            return ForensicsSummaryService._build_document_summary(result)
        return ForensicsSummaryService._base_summary(
            file_type=file_type,
            verification_method="Unknown",
            tampered=bool(result.get("tampered", False)),
            confidence=float(result.get("confidence", 0.0) or 0.0),
            supporting_evidence=["No phase-2 forensic summary available for this file type."],
        )

    @staticmethod
    def build_from_records(file_type: str, records: List[Any]) -> Dict[str, Any]:
        normalized = [
            {
                "engine_name": getattr(record, "engine_name", "Unknown"),
                "tampered": bool(getattr(record, "tampered", False)),
                "confidence": float(getattr(record, "confidence", 0.0) or 0.0),
                "output_details": getattr(record, "output_details", {}) or {},
            }
            for record in records
        ]

        if file_type == "image":
            details = {
                "ela": ForensicsSummaryService._first_matching_output(normalized, "ela"),
                "noise": ForensicsSummaryService._first_matching_output(normalized, "noise"),
                "clone_detection": ForensicsSummaryService._first_matching_output(normalized, "clone"),
                "jpeg_ghost": ForensicsSummaryService._first_matching_output(normalized, "ghost"),
            }
            return ForensicsSummaryService._build_image_summary({"details": details})
        if file_type == "video":
            return ForensicsSummaryService._build_video_summary(
                {
                    "forensics_findings": {
                        "reasons": ForensicsSummaryService._record_reasons(normalized),
                        "confidence": ForensicsSummaryService._average_confidence(normalized),
                    },
                    "tampered": any(item["tampered"] for item in normalized),
                    "confidence": ForensicsSummaryService._average_confidence(normalized),
                }
            )
        if file_type == "audio":
            return ForensicsSummaryService._build_audio_summary({"reasons": ForensicsSummaryService._record_reasons(normalized), "tampered": any(item["tampered"] for item in normalized), "confidence": ForensicsSummaryService._average_confidence(normalized)})
        if file_type == "document":
            return ForensicsSummaryService._build_document_summary({"reasons": ForensicsSummaryService._record_reasons(normalized), "details": ForensicsSummaryService._record_details(normalized), "tampered": any(item["tampered"] for item in normalized), "confidence": ForensicsSummaryService._average_confidence(normalized)})

        return ForensicsSummaryService._base_summary(
            file_type=file_type,
            verification_method="Unknown",
            tampered=any(item["tampered"] for item in normalized),
            confidence=ForensicsSummaryService._average_confidence(normalized),
            supporting_evidence=ForensicsSummaryService._record_reasons(normalized),
        )

    @staticmethod
    def _build_image_summary(result: Dict[str, Any]) -> Dict[str, Any]:
        details = result.get("details", {}) or {}
        ella = details.get("ela", {}) or {}
        noise = details.get("noise", {}) or {}
        clone = details.get("clone_detection", {}) or {}
        ghost = details.get("jpeg_ghost", {}) or {}

        supporting_evidence: List[str] = []
        modified_regions: List[str] = []
        methods = [
            "Error Level Analysis",
            "Noise Dispersion Analysis",
            "Clone Similarity Matching",
            "JPEG Ghost Detection",
        ]

        if ella.get("tampered"):
            supporting_evidence.append("ELA energy delta exceeded tamper threshold.")
            if ella.get("output_image_path"):
                supporting_evidence.append(f"ELA visualization stored at {ella['output_image_path']}.")
        if noise.get("tampered"):
            stats = noise.get("statistics", {}) or {}
            supporting_evidence.append(
                f"Noise anomaly ratio {stats.get('anomaly_ratio', 'n/a')} with dispersion {stats.get('variance_dispersion', 'n/a')}."
            )
        if clone.get("tampered"):
            modified_regions.extend(ForensicsSummaryService._clone_regions_to_strings(clone.get("modified_regions", [])))
            supporting_evidence.append(f"Clone detection found {len(clone.get('modified_regions', []))} suspect matching block pairs.")
        if ghost.get("tampered"):
            supporting_evidence.append(f"JPEG ghost estimation indicated prior recompression quality near {ghost.get('detected_original_quality', 'n/a')}.")

        if not supporting_evidence:
            supporting_evidence.append("No ELA, noise, clone, or JPEG ghost anomalies detected.")

        confidence = ForensicsSummaryService._average_confidence(
            [
                {"confidence": ella.get("confidence", 0.0), "tampered": ella.get("tampered", False)},
                {"confidence": noise.get("confidence", 0.0), "tampered": noise.get("tampered", False)},
                {"confidence": clone.get("confidence", 0.0), "tampered": clone.get("tampered", False)},
                {"confidence": ghost.get("confidence", 0.0), "tampered": ghost.get("tampered", False)},
            ]
        )

        tampered = bool(ella.get("tampered") or noise.get("tampered") or clone.get("tampered") or ghost.get("tampered"))

        return ForensicsSummaryService._base_summary(
            file_type="image",
            verification_method="ELA + Noise + Clone Similarity + JPEG Ghost",
            tampered=tampered,
            confidence=confidence,
            supporting_evidence=supporting_evidence,
            modified_regions=modified_regions,
        )

    @staticmethod
    def _build_video_summary(result: Dict[str, Any]) -> Dict[str, Any]:
        findings = result.get("forensics_findings", {}) or {}
        reasons = findings.get("reasons", []) or []
        metadata = result.get("metadata", {}) or {}
        supporting_evidence = list(reasons)

        if metadata.get("software"):
            supporting_evidence.append(f"Container tags reference re-encoding software: {metadata['software']}.")
        if metadata.get("codec"):
            supporting_evidence.append(f"Primary codec detected as {metadata['codec']}.")

        return ForensicsSummaryService._base_summary(
            file_type="video",
            verification_method="FFprobe metadata + binary container structure",
            tampered=bool(result.get("tampered", False)),
            confidence=float(result.get("confidence", findings.get("confidence", 0.0)) or 0.0),
            supporting_evidence=supporting_evidence or ["No video structural anomalies detected."],
            modified_regions=[],
        )

    @staticmethod
    def _build_audio_summary(result: Dict[str, Any]) -> Dict[str, Any]:
        reasons = list(result.get("reasons", []) or [])
        stats = result.get("stats", {}) or {}
        if stats:
            reasons.append(
                f"Audio profile: {stats.get('sample_rate_hz', 'n/a')} Hz, {stats.get('channels', 'n/a')} channels, {stats.get('bitrate_kbps', 'n/a')} kbps."
            )

        return ForensicsSummaryService._base_summary(
            file_type="audio",
            verification_method="Spectrogram + acoustic profile + noise-floor analysis",
            tampered=bool(result.get("tampered", False)),
            confidence=float(result.get("confidence", 0.0) or 0.0),
            supporting_evidence=reasons or ["No voice cloning or acoustic discontinuity detected."],
            modified_regions=[],
        )

    @staticmethod
    def _build_document_summary(result: Dict[str, Any]) -> Dict[str, Any]:
        reasons = list(result.get("reasons", []) or [])
        details = result.get("details", {}) or {}
        if details:
            for key, label in (
                ("javascript_count", "JavaScript objects"),
                ("js_count", "JS tokens"),
                ("open_action_count", "OpenAction triggers"),
                ("launch_count", "Launch commands"),
                ("embedded_files_count", "Embedded files"),
                ("incremental_updates_count", "Incremental updates"),
            ):
                value = details.get(key)
                if value:
                    reasons.append(f"{label}: {value}.")

        return ForensicsSummaryService._base_summary(
            file_type="document",
            verification_method="PDFID/PeePDF-style structural audit + OOXML archive inspection",
            tampered=bool(result.get("tampered", False)),
            confidence=float(result.get("confidence", 0.0) or 0.0),
            supporting_evidence=reasons or ["No structural document anomalies detected."],
            modified_regions=[],
        )

    @staticmethod
    def _base_summary(
        *,
        file_type: str,
        verification_method: str,
        tampered: bool,
        confidence: float,
        supporting_evidence: List[str],
        modified_regions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return {
            "file_type": file_type,
            "tampered": tampered,
            "confidence_score": round(confidence, 2),
            "verification_method": verification_method,
            "supporting_evidence": supporting_evidence,
            "modified_regions": modified_regions or [],
            "risk_signal": "tampering" if tampered else "clean",
        }

    @staticmethod
    def _record_reasons(records: List[Dict[str, Any]]) -> List[str]:
        reasons: List[str] = []
        for record in records:
            details = record.get("output_details", {}) or {}
            record_reasons = details.get("reasons")
            if isinstance(record_reasons, list):
                reasons.extend(str(reason) for reason in record_reasons)
            elif record_reasons:
                reasons.append(str(record_reasons))
        return reasons

    @staticmethod
    def _record_details(records: List[Dict[str, Any]]) -> Dict[str, Any]:
        details: Dict[str, Any] = {}
        for record in records:
            if record.get("output_details"):
                details[record["engine_name"]] = record["output_details"]
        return details

    @staticmethod
    def _records_to_findings(records: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings: Dict[str, Any] = {}
        for record in records:
            key = record["engine_name"].lower().replace(" ", "_")
            findings[key] = record["output_details"]
        return findings

    @staticmethod
    def _average_confidence(records: List[Dict[str, Any]]) -> float:
        values = [float(record.get("confidence", 0.0) or 0.0) for record in records if record.get("confidence") is not None]
        if not values:
            return 0.0
        return round(sum(values) / len(values), 2)

    @staticmethod
    def _clone_regions_to_strings(regions: List[Dict[str, Any]]) -> List[str]:
        formatted: List[str] = []
        for region in regions:
            source_block = region.get("source_block")
            target_block = region.get("target_block")
            distance = region.get("hamming_distance")
            formatted.append(f"{source_block} -> {target_block} (distance {distance})")
        return formatted

    @staticmethod
    def _first_matching_output(records: List[Dict[str, Any]], needle: str) -> Dict[str, Any]:
        for record in records:
            engine_name = str(record.get("engine_name", "")).lower()
            if needle in engine_name:
                return record.get("output_details", {}) or {}
        return {}
