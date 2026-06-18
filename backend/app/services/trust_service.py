from typing import Dict, Any
from sqlmodel import Session, select
from app.models.schemas import Evidence, Upload, Hashes, MetadataRecord, ForensicsResult, ProvenanceRecord, DeepfakeResult, AIAttributionResult, BlockchainRecord
from app.services.blockchain_assessment import BlockchainAssessmentService
from app.services.claim_consistency_service import ClaimConsistencyService
from app.services.deepfake_assessment import DeepfakeAssessmentService
from app.services.forensics_summary import ForensicsSummaryService
from app.services.provenance_service import ProvenanceService

class TrustService:
    @staticmethod
    def calculate_score(db: Session, evidence_id: str) -> Dict[str, Any]:
        """
        Dynamically calculates the 0-100 Trust Score and risk level for an evidence item.
        Combines metadata trust, integrity, malware flags, duplicate indicators, forensic analysis, and digital provenance.
        """
        evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
        if not evidence:
            return {"error": "Evidence not found"}

        upload = db.exec(select(Upload).where(Upload.evidence_id == evidence_id)).first()
        metadata_rec = db.exec(select(MetadataRecord).where(MetadataRecord.evidence_id == evidence_id)).first()

        # Starting base score
        score = 100.0
        reasons = []

        # 1. Malware Check (High impact)
        if upload and not upload.malware_scan_passed:
            score = 0.0
            reasons.append("Malware scan failed: Malicious signatures detected")
            evidence.trust_score = 0.0
            evidence.risk_level = "CRITICAL"
            db.add(evidence)
            db.commit()
            db.refresh(evidence)
            return {
                "evidence_id": evidence_id,
                "trust_score": 0.0,
                "risk_level": "CRITICAL",
                "reasons": reasons
            }

        # 2. Integrity Check (High impact)
        if upload and not upload.integrity_valid:
            score = min(score, 10.0)
            reasons.append("Integrity validation failed: File extension does not match binary headers")

        # 3. Metadata analysis
        if metadata_rec:
            # Check for software used
            software = metadata_rec.software_used
            if software:
                software_lower = software.lower()
                editors = ["photoshop", "gimp", "canva", "illustrator", "premiere", "imovie", "exiftool", "ffmpeg"]
                for editor in editors:
                    if editor in software_lower:
                        score -= 25.0
                        reasons.append(f"Editing software signature found in metadata: {software}")
                        break
            
            # Check for missing creation date in structural media
            if evidence.file_type in ["image", "video"] and not metadata_rec.created_datetime:
                score -= 10.0
                reasons.append("Original acquisition/creation date is missing from metadata structures")
        else:
            # If no metadata could be extracted at all (for image/document)
            if evidence.file_type in ["image", "document"]:
                score -= 15.0
                reasons.append("Failed to extract standard structural metadata header structures")

        # 4. Duplicate checks
        if upload and upload.duplicate_detected:
            score -= 5.0
            reasons.append("Identical file hash already cataloged in the database")

        # 5. Deep Forensics Checks
        forensics = db.exec(select(ForensicsResult).where(ForensicsResult.evidence_id == evidence_id)).all()
        for f in forensics:
            if f.tampered:
                # Deduct based on forensics results
                if "ELA" in f.engine_name:
                    score -= 30.0
                    reasons.append(f"Forensics anomaly: JPEG ELA compression level mismatch ({f.confidence}% confidence)")
                elif "CLONE" in f.engine_name:
                    score -= 40.0
                    reasons.append("Forensics anomaly: Embedded pixel copy-paste clones detected")
                elif "NOISE" in f.engine_name:
                    score -= 20.0
                    reasons.append("Forensics anomaly: High-frequency noise floor splicing discontinuity")
                elif "Video" in f.engine_name:
                    score -= 35.0
                    reasons.append("Forensics anomaly: Video container timecode or structural mismatch")
                elif "Audio" in f.engine_name:
                    score -= 40.0
                    reasons.append("Forensics anomaly: Synthetic/voice-cloning speech harmonics detected")
                elif "Document" in f.engine_name:
                    score -= 35.0
                    reasons.append("Forensics anomaly: Active Javascript payloads or incremental edits in document")

        # 6. C2PA Provenance Checks
        provenance = db.exec(select(ProvenanceRecord).where(ProvenanceRecord.evidence_id == evidence_id)).first()
        has_valid_provenance = False
        if provenance and provenance.has_manifest:
            if provenance.manifest_valid:
                score += 15.0
                has_valid_provenance = True
                reasons.append("Provenance verified: C2PA Content Credentials matches a trusted signature key (+15 boost)")
            else:
                score = min(score, 10.0)
                reasons.append("CRITICAL: C2PA Content Credentials signature mismatch or broken manifest hashes detected")

        # 7. Deepfake Results checks
        deepfake = db.exec(select(DeepfakeResult).where(DeepfakeResult.evidence_id == evidence_id)).first()
        if deepfake:
            prob = deepfake.deepfake_probability
            if prob > 0.80:
                score = 0.0
                reasons.append(f"Deepfake detected: High probability deepfake content ({prob * 100:.1f}%)")
                evidence.trust_score = 0.0
                evidence.risk_level = "CRITICAL"
                db.add(evidence)
                db.commit()
                db.refresh(evidence)
                return {
                    "evidence_id": evidence_id,
                    "trust_score": 0.0,
                    "risk_level": "CRITICAL",
                    "reasons": reasons
                }
            elif prob > 0.45:
                score -= 45.0
                reasons.append(f"Deepfake warning: Probable deepfake content detected ({prob * 100:.1f}%)")

        # 8. AI Attribution checks
        ai_attr = db.exec(select(AIAttributionResult).where(AIAttributionResult.evidence_id == evidence_id)).first()
        is_ai_without_c2pa = False
        if ai_attr:
            is_ai = ai_attr.predicted_source not in ["Human/Unknown", "Human / Camera Original"]
            if is_ai and not has_valid_provenance:
                score -= 20.0
                is_ai_without_c2pa = True
                reasons.append(f"Unverified AI-generated content source: {ai_attr.predicted_source} without valid Content Credentials")

        # 9. Blockchain Custody check
        blockchain = db.exec(select(BlockchainRecord).where(BlockchainRecord.evidence_id == evidence_id)).first()
        if blockchain:
            score += 10.0
            reasons.append(f"Blockchain custody verified: anchored on {blockchain.chain_name} (Block #{blockchain.block_number}) (+10 custody boost)")

        hashes_rec = db.exec(select(Hashes).where(Hashes.evidence_id == evidence_id)).first()
        forensics_summary = ForensicsSummaryService.build_from_records(evidence.file_type, forensics)
        deepfake_assessment = DeepfakeAssessmentService.build_from_record(evidence.file_type, deepfake)
        provenance_assessment = None
        if provenance:
            provenance_assessment = ProvenanceService.assess_provenance(
                upload.storage_path if upload else "",
                metadata={
                    "creator": metadata_rec.creator if metadata_rec else None,
                    "device": provenance.device,
                    "editing_history": provenance.editing_history,
                    "software_used": metadata_rec.software_used if metadata_rec else None,
                },
                blockchain_verified=bool(blockchain),
            )
        blockchain_assessment = BlockchainAssessmentService.build(
            blockchain,
            evidence_hash=hashes_rec.sha256 if hashes_rec else None,
            provenance_assessment=provenance_assessment,
            trust_score=score,
        )
        claim_assessment = ClaimConsistencyService.assess(
            filename=evidence.filename,
            file_type=evidence.file_type,
            metadata={
                "creator": metadata_rec.creator if metadata_rec else None,
                "software_used": metadata_rec.software_used if metadata_rec else None,
                "device": provenance.device if provenance else None,
            },
            raw_metadata=metadata_rec.raw_metadata if metadata_rec else {},
            upload=upload,
            forensics_summary=forensics_summary,
            provenance_assessment=provenance_assessment or {},
            deepfake_assessment=deepfake_assessment,
            ai_attribution=ai_attr,
            blockchain_assessment=blockchain_assessment,
        )
        if claim_assessment["is_conflict"]:
            if claim_assessment["severity"] in {"HIGH", "CRITICAL"}:
                score = min(score, 10.0)
            else:
                score = min(score, 20.0)
            reasons.append(f"Claim conflict detected: {claim_assessment['conflict_type']} ({claim_assessment['severity']}).")
            reasons.extend(claim_assessment["supporting_evidence"][:2])

        # Bound score between 0 and 100
        score = max(0.0, min(100.0, score))

        # Risk Classification mapping
        if score >= 85:
            risk_level = "LOW"
        elif score >= 50:
            risk_level = "MEDIUM"
        elif score >= 20:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        # Apply specific overrides:
        # If AI generated and lacks verified C2PA, risk level must be at least MEDIUM (i.e., if it is LOW, force it to MEDIUM)
        if is_ai_without_c2pa:
            if risk_level == "LOW":
                risk_level = "MEDIUM"

        # Update evidence in database
        evidence.trust_score = score
        evidence.risk_level = risk_level
        db.add(evidence)
        db.commit()
        db.refresh(evidence)

        # Build verification methods
        verification_methods = ["Cryptographic Hash Digest"]
        if upload and upload.integrity_valid:
            verification_methods.append("Binary Magic Bytes Ingestion Signature")
        if metadata_rec:
            verification_methods.append("Metadata Structure Properties extraction")
        if forensics:
            verification_methods.append("Deep Forensic Spectral & Noise Audits")
        if provenance and provenance.has_manifest:
            verification_methods.append("C2PA Content Credentials Manifest Chain")
        if deepfake:
            verification_methods.append("Deepfake Biometric Distortion Scanning")
        if ai_attr:
            verification_methods.append("Generative Model Attribution Signature Checking")
        if blockchain:
            verification_methods.append("Blockchain Public Ledger Anchor Custody")
        if claim_assessment["is_conflict"]:
            verification_methods.append("Claim-vs-Content Consistency Review")

        return {
            "evidence_id": evidence_id,
            "trust_score": score,
            "risk_level": risk_level,
            "reasons": reasons,
            "confidence_score": score,
            "supporting_evidence": reasons,
            "verification_methods": verification_methods
            ,"claim_assessment": claim_assessment,
            "forensics_summary": forensics_summary,
            "deepfake_assessment": deepfake_assessment,
            "provenance_assessment": provenance_assessment,
            "blockchain_assessment": blockchain_assessment,
        }
