from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Request
from sqlmodel import Session, select

from app.models.schemas import DocumentTrace, Evidence, MetadataRecord, Upload, User, UserSession


class ForensicTraceService:
    @staticmethod
    def upsert_user_session(
        db: Session,
        *,
        session_id: str,
        user: User,
        request: Optional[Request] = None,
    ) -> UserSession:
        user_agent = request.headers.get("user-agent") if request else None
        ip_address = request.client.host if request and request.client else None
        existing = db.exec(select(UserSession).where(UserSession.session_id == session_id)).first()
        if existing:
            existing.user_id = user.id or existing.user_id
            existing.user_email = user.email
            existing.user_agent = user_agent or existing.user_agent
            existing.ip_address = ip_address or existing.ip_address
            existing.active = True
            existing.last_seen_at = datetime.now(timezone.utc)
            db.add(existing)
            db.commit()
            db.refresh(existing)
            return existing

        record = UserSession(
            session_id=session_id,
            user_id=user.id,
            user_email=user.email,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def create_upload_trace(
        db: Session,
        *,
        session_id: str,
        user: User,
        evidence: Evidence,
        upload: Upload,
        metadata: Optional[MetadataRecord],
        raw_metadata: Optional[Dict[str, Any]],
    ) -> DocumentTrace:
        existing = db.exec(select(DocumentTrace).where(DocumentTrace.evidence_id == evidence.id)).first()
        if existing:
            db.delete(existing)
            db.commit()

        trace = DocumentTrace(
            session_id=session_id,
            evidence_id=evidence.id,
            user_id=user.id,
            user_email=user.email,
            filename=evidence.filename,
            file_type=evidence.file_type,
            mime_type=evidence.mime_type,
            file_size_bytes=evidence.size_bytes,
            extracted_content_summary=ForensicTraceService._content_summary(evidence, upload, metadata),
            model_input_prompt=ForensicTraceService._build_prompt(
                evidence=evidence,
                upload=upload,
                metadata=metadata,
                raw_metadata=raw_metadata or {},
            ),
            processing_steps=[
                {"stage": "upload", "status": "success" if upload.integrity_valid else "warning"},
                {"stage": "metadata_extraction", "status": "success" if metadata else "warning"},
            ],
            intermediate_reasoning={
                "upload": {
                    "integrity_valid": upload.integrity_valid,
                    "malware_scan_passed": upload.malware_scan_passed,
                    "duplicate_detected": upload.duplicate_detected,
                    "storage_path": upload.storage_path,
                },
                "metadata": metadata.raw_metadata if metadata else {},
            },
            warnings=ForensicTraceService._upload_warnings(upload, metadata),
            token_usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "estimated": False},
            fallback_behavior={"used": False, "reason": None},
        )
        db.add(trace)
        db.commit()
        db.refresh(trace)
        return trace

    @staticmethod
    def update_analysis_trace(
        db: Session,
        *,
        trace: DocumentTrace,
        evidence: Evidence,
        metadata: Optional[MetadataRecord],
        forensics_summary: Dict[str, Any],
        provenance_assessment: Optional[Dict[str, Any]],
        deepfake_assessment: Dict[str, Any],
        ai_attribution: Optional[Any],
        blockchain_assessment: Dict[str, Any],
        claim_assessment: Optional[Dict[str, Any]],
        trust_assessment: Dict[str, Any],
        analysis_steps: Optional[List[Dict[str, Any]]] = None,
        errors: Optional[List[str]] = None,
        warnings: Optional[List[str]] = None,
        duration_ms: Optional[float] = None,
    ) -> DocumentTrace:
        trace.extracted_content_summary = ForensicTraceService._content_summary_from_analysis(
            evidence=evidence,
            metadata=metadata,
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment or {},
            deepfake_assessment=deepfake_assessment,
            ai_attribution=ai_attribution,
            claim_assessment=claim_assessment or {},
            trust_assessment=trust_assessment,
        )
        trace.model_input_prompt = ForensicTraceService._build_prompt_from_analysis(
            evidence=evidence,
            metadata=metadata,
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment or {},
            deepfake_assessment=deepfake_assessment,
            ai_attribution=ai_attribution,
            claim_assessment=claim_assessment or {},
        )
        trace.processing_steps = analysis_steps or ForensicTraceService._analysis_steps(
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment or {},
            deepfake_assessment=deepfake_assessment,
            ai_attribution=ai_attribution,
            blockchain_assessment=blockchain_assessment,
            claim_assessment=claim_assessment or {},
        )
        trace.intermediate_reasoning = {
            "forensics": forensics_summary,
            "provenance": provenance_assessment or {},
            "deepfake": deepfake_assessment,
            "ai_attribution": ForensicTraceService._serialize_ai_attribution(ai_attribution),
            "blockchain": blockchain_assessment,
            "claim_consistency": claim_assessment or {},
            "trust": trust_assessment,
        }
        trace.model_output = {
            "forensics_summary": forensics_summary,
            "provenance_assessment": provenance_assessment,
            "deepfake_assessment": deepfake_assessment,
            "ai_attribution": ForensicTraceService._serialize_ai_attribution(ai_attribution),
            "blockchain_assessment": blockchain_assessment,
            "claim_assessment": claim_assessment,
            "trust_assessment": trust_assessment,
        }
        trace.classifications = {
            "trust_risk_level": trust_assessment.get("risk_level"),
            "trust_verdict": trust_assessment.get("verdict"),
            "provenance_owner": (provenance_assessment or {}).get("ownership_classification"),
            "deepfake_risk_level": deepfake_assessment.get("risk_level"),
            "claim_conflict": (claim_assessment or {}).get("conflict_type"),
        }
        trace.extracted_entities = ForensicTraceService._extracted_entities(
            metadata=metadata,
            ai_attribution=ai_attribution,
            claim_assessment=claim_assessment or {},
            blockchain_assessment=blockchain_assessment,
        )
        trace.warnings = ForensicTraceService._merge_messages(trace.warnings, warnings)
        trace.errors = ForensicTraceService._merge_messages(trace.errors, errors)
        trace.fallback_behavior = ForensicTraceService._fallback_behavior(
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment or {},
            deepfake_assessment=deepfake_assessment,
            ai_attribution=ai_attribution,
            claim_assessment=claim_assessment or {},
        )
        trace.token_usage = ForensicTraceService._token_usage(trace.model_input_prompt, trust_assessment)
        trace.processing_duration_ms = duration_ms
        trace.confidence_score = trust_assessment.get("confidence_score")
        trace.updated_at = datetime.now(timezone.utc)
        db.add(trace)
        db.commit()
        db.refresh(trace)
        return trace

    @staticmethod
    def _content_summary(
        evidence: Evidence,
        upload: Optional[Upload],
        metadata: Optional[MetadataRecord],
    ) -> str:
        summary_parts = [
            f"{evidence.file_type} evidence {evidence.filename}",
            f"size={evidence.size_bytes} bytes",
            f"mime={evidence.mime_type}",
        ]
        if upload:
            summary_parts.append(f"integrity={upload.integrity_valid}")
            summary_parts.append(f"malware={upload.malware_scan_passed}")
        if metadata:
            if metadata.creator:
                summary_parts.append(f"creator={metadata.creator}")
            if metadata.software_used:
                summary_parts.append(f"software={metadata.software_used}")
            if metadata.created_datetime:
                summary_parts.append(f"created={metadata.created_datetime.isoformat()}")
        return " | ".join(summary_parts)

    @staticmethod
    def _content_summary_from_analysis(
        *,
        evidence: Evidence,
        metadata: Optional[MetadataRecord],
        forensics_summary: Dict[str, Any],
        provenance_assessment: Dict[str, Any],
        deepfake_assessment: Dict[str, Any],
        ai_attribution: Optional[Any],
        claim_assessment: Dict[str, Any],
        trust_assessment: Dict[str, Any],
    ) -> str:
        summary = ForensicTraceService._content_summary(evidence, None, metadata)
        snippets = [
            f"forensics={forensics_summary.get('verification_method', 'n/a')}",
            f"provenance={provenance_assessment.get('ownership_classification', 'UNKNOWN OWNER')}",
            f"deepfake={deepfake_assessment.get('risk_level', 'LOW')}",
            f"claim={claim_assessment.get('conflict_type', 'consistent')}",
            f"trust={trust_assessment.get('risk_level', 'n/a')}",
        ]
        if ai_attribution:
            snippets.append(f"ai_source={getattr(ai_attribution, 'predicted_source', 'n/a')}")
        return summary + " || " + " | ".join(snippets)

    @staticmethod
    def _build_prompt(
        *,
        evidence: Evidence,
        upload: Optional[Upload],
        metadata: Optional[MetadataRecord],
        raw_metadata: Dict[str, Any],
    ) -> str:
        payload = {
            "task": "Deep forensic document analysis",
            "evidence_id": evidence.id,
            "file_name": evidence.filename,
            "file_type": evidence.file_type,
            "mime_type": evidence.mime_type,
            "file_size_bytes": evidence.size_bytes,
            "upload_integrity_valid": getattr(upload, "integrity_valid", None),
            "upload_malware_scan_passed": getattr(upload, "malware_scan_passed", None),
            "metadata": {
                "creator": getattr(metadata, "creator", None),
                "software_used": getattr(metadata, "software_used", None),
                "created_datetime": getattr(metadata, "created_datetime", None).isoformat() if getattr(metadata, "created_datetime", None) else None,
                "modified_datetime": getattr(metadata, "modified_datetime", None).isoformat() if getattr(metadata, "modified_datetime", None) else None,
            },
            "raw_metadata": raw_metadata,
            "instructions": [
                "Extract content summary",
                "Run hash validation",
                "Run provenance assessment",
                "Run deepfake / AI attribution checks",
                "Return confidence, classifications, entities, warnings, and errors",
            ],
        }
        return json.dumps(payload, default=str, indent=2)

    @staticmethod
    def _build_prompt_from_analysis(
        *,
        evidence: Evidence,
        metadata: Optional[MetadataRecord],
        forensics_summary: Dict[str, Any],
        provenance_assessment: Dict[str, Any],
        deepfake_assessment: Dict[str, Any],
        ai_attribution: Optional[Any],
        claim_assessment: Dict[str, Any],
    ) -> str:
        payload = {
            "task": "Deep forensic document analysis",
            "evidence_id": evidence.id,
            "file_name": evidence.filename,
            "file_type": evidence.file_type,
            "metadata_creator": getattr(metadata, "creator", None),
            "metadata_software": getattr(metadata, "software_used", None),
            "forensics_method": forensics_summary.get("verification_method"),
            "provenance": provenance_assessment.get("ownership_classification"),
            "deepfake_risk": deepfake_assessment.get("risk_level"),
            "ai_source": getattr(ai_attribution, "predicted_source", None) if ai_attribution else None,
            "claim_consistency": claim_assessment.get("conflict_type", "consistent"),
            "instructions": [
                "Summarize content with evidence-specific context",
                "Preserve per-document reasoning and classifications",
                "Report any conflicts between the claimed origin and content-derived origin",
            ],
        }
        return json.dumps(payload, default=str, indent=2)

    @staticmethod
    def _analysis_steps(
        *,
        forensics_summary: Dict[str, Any],
        provenance_assessment: Dict[str, Any],
        deepfake_assessment: Dict[str, Any],
        ai_attribution: Optional[Any],
        blockchain_assessment: Dict[str, Any],
        claim_assessment: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        return [
            {"stage": "forensics", "status": "completed", "summary": forensics_summary.get("verification_method")},
            {"stage": "provenance", "status": "completed", "summary": provenance_assessment.get("verification_method")},
            {"stage": "deepfake", "status": "completed", "summary": deepfake_assessment.get("verification_method")},
            {"stage": "ai_attribution", "status": "completed", "summary": getattr(ai_attribution, "predicted_source", "unavailable") if ai_attribution else "unavailable"},
            {"stage": "blockchain", "status": "completed" if blockchain_assessment.get("anchored") else "not_present"},
            {"stage": "claim_consistency", "status": "completed" if claim_assessment.get("is_conflict") else "clean", "summary": claim_assessment.get("conflict_type", "consistent")},
        ]

    @staticmethod
    def _extracted_entities(
        *,
        metadata: Optional[MetadataRecord],
        ai_attribution: Optional[Any],
        claim_assessment: Dict[str, Any],
        blockchain_assessment: Dict[str, Any],
    ) -> Dict[str, Any]:
        entities: Dict[str, Any] = {}
        if metadata and metadata.creator:
            entities["creator"] = metadata.creator
        if metadata and metadata.software_used:
            entities["software_used"] = metadata.software_used
        if ai_attribution:
            entities["predicted_source"] = getattr(ai_attribution, "predicted_source", None)
        if claim_assessment.get("claim_terms"):
            entities["claim_terms"] = claim_assessment["claim_terms"][:6]
        if blockchain_assessment.get("registered_owner"):
            entities["registered_owner"] = blockchain_assessment["registered_owner"]
        return entities

    @staticmethod
    def _upload_warnings(upload: Optional[Upload], metadata: Optional[MetadataRecord]) -> List[str]:
        warnings: List[str] = []
        if upload and not upload.integrity_valid:
            warnings.append("Integrity validation failed during upload.")
        if upload and not upload.malware_scan_passed:
            warnings.append("Malware scan failed during upload.")
        if upload and upload.duplicate_detected:
            warnings.append("Duplicate evidence detected during upload.")
        if metadata is None:
            warnings.append("No metadata record available at upload time.")
        return warnings

    @staticmethod
    def _fallback_behavior(
        *,
        forensics_summary: Dict[str, Any],
        provenance_assessment: Dict[str, Any],
        deepfake_assessment: Dict[str, Any],
        ai_attribution: Optional[Any],
        claim_assessment: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "forensics_fallback": forensics_summary.get("verification_method") == "Unknown",
            "provenance_fallback": not bool(provenance_assessment.get("supporting_evidence")),
            "deepfake_fallback": deepfake_assessment.get("verification_method") == "Heuristic deepfake risk assessment",
            "ai_attribution_fallback": ai_attribution is None,
            "claim_consistency_fallback": claim_assessment.get("claim_label") == "UNSPECIFIED",
        }

    @staticmethod
    def _token_usage(prompt_text: str, trust_assessment: Dict[str, Any]) -> Dict[str, Any]:
        prompt_tokens = max(1, len(prompt_text) // 4)
        completion_tokens = max(1, len(json.dumps(trust_assessment, default=str)) // 4)
        return {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "estimated": True,
        }

    @staticmethod
    def _merge_messages(existing: List[str], extra: Optional[List[str]]) -> List[str]:
        merged = list(existing or [])
        if extra:
            merged.extend(extra)
        deduped: List[str] = []
        for item in merged:
            if item and item not in deduped:
                deduped.append(item)
        return deduped

    @staticmethod
    def _serialize_ai_attribution(ai_attribution: Optional[Any]) -> Dict[str, Any]:
        if not ai_attribution:
            return {}
        return {
            "predicted_source": getattr(ai_attribution, "predicted_source", None),
            "probability": getattr(ai_attribution, "probability", None),
            "confidence": getattr(ai_attribution, "confidence", None),
            "indicators": getattr(ai_attribution, "indicators", {}) or {},
        }
