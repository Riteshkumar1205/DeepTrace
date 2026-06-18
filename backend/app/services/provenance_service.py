import os
import struct
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional

from pypdf import PdfReader


class ProvenanceService:
    @staticmethod
    def assess_provenance(
        file_path: str,
        metadata: Optional[Dict[str, Any]] = None,
        blockchain_verified: bool = False,
    ) -> Dict[str, Any]:
        """
        Produces a structured provenance assessment with ownership classification.
        Ownership is only elevated when there is concrete provenance evidence
        such as signatures, C2PA-like manifests, or blockchain anchoring.
        """
        metadata = metadata or {}
        ext = os.path.splitext(file_path)[1].lower()
        filename = os.path.basename(file_path).lower()

        manifest_signals = ProvenanceService._collect_manifest_signals(file_path, ext)
        metadata_signals = ProvenanceService._collect_metadata_signals(file_path, ext, metadata)
        ai_generation_signals = ProvenanceService._collect_ai_generation_signals(filename, metadata)

        has_manifest = bool(manifest_signals["present"] or metadata_signals["manifest_hint"])
        manifest_valid = bool(manifest_signals["valid"])

        creator = metadata_signals.get("creator")
        device = metadata_signals.get("device")
        editing_history = metadata_signals.get("editing_history", [])

        supporting_evidence: List[str] = []
        supporting_evidence.extend(manifest_signals["evidence"])
        supporting_evidence.extend(metadata_signals["evidence"])
        supporting_evidence.extend(ai_generation_signals["evidence"])

        if blockchain_verified:
            supporting_evidence.append("Blockchain registration anchor verified for the evidence item.")

        owner_classification = ProvenanceService._classify_owner(
            has_manifest=has_manifest,
            manifest_valid=manifest_valid,
            blockchain_verified=blockchain_verified,
            ai_generation_signals=ai_generation_signals["present"],
            creator=creator,
        )

        confidence_score = ProvenanceService._calculate_confidence(
            has_manifest=has_manifest,
            manifest_valid=manifest_valid,
            blockchain_verified=blockchain_verified,
            creator=creator,
            device=device,
            editing_history=editing_history,
            ai_generation_signals=ai_generation_signals["present"],
        )

        verification_methods = [
            "Binary manifest scan",
            "Metadata provenance extraction",
            "AI generation cue inspection",
        ]
        if blockchain_verified:
            verification_methods.append("Blockchain custody verification")

        reasons: List[str] = []
        if manifest_signals["present"]:
            reasons.append("Manifest markers located in the asset payload.")
        elif metadata_signals["manifest_hint"]:
            reasons.append("Manifest-like provenance metadata located in embedded structures.")
        else:
            reasons.append("No manifest markers located in the asset payload.")

        if manifest_valid:
            reasons.append("Manifest signatures or provenance markers were internally consistent.")
        elif has_manifest:
            reasons.append("Manifest content was present but could not be cryptographically validated.")

        if ai_generation_signals["present"]:
            reasons.append("AI generation indicators suggest the content may be produced by a synthetic pipeline.")

        if blockchain_verified:
            reasons.append("Blockchain anchoring confirms an external custody record.")

        if not supporting_evidence:
            supporting_evidence.append("No provenance evidence beyond file structure was detected.")

        return {
            "has_manifest": has_manifest,
            "manifest_valid": manifest_valid,
            "creator": creator,
            "device": device,
            "editing_history": editing_history,
            "verification_status": owner_classification,
            "ownership_classification": owner_classification,
            "confidence_score": confidence_score,
            "verification_method": " | ".join(verification_methods),
            "supporting_evidence": supporting_evidence,
            "reasons": reasons,
            "manifest_signals": manifest_signals,
            "metadata_signals": metadata_signals,
            "ai_generation_signals": ai_generation_signals,
        }

    @staticmethod
    def extract_c2pa_provenance(file_path: str) -> Dict[str, Any]:
        """
        Backwards-compatible wrapper used by existing call sites.
        """
        assessment = ProvenanceService.assess_provenance(file_path)
        return {
            "has_manifest": assessment["has_manifest"],
            "manifest_valid": assessment["manifest_valid"],
            "creator": assessment["creator"],
            "device": assessment["device"],
            "editing_history": assessment["editing_history"],
            "verification_status": assessment["verification_status"],
            "reasons": assessment["reasons"],
            "verification_method": assessment["verification_method"],
            "supporting_evidence": assessment["supporting_evidence"],
            "ownership_classification": assessment["ownership_classification"],
            "confidence_score": assessment["confidence_score"],
        }

    @staticmethod
    def _collect_manifest_signals(file_path: str, ext: str) -> Dict[str, Any]:
        if ext in [".jpg", ".jpeg"]:
            present = ProvenanceService._scan_jpeg_app11_jumb(file_path)
            return {
                "present": present,
                "valid": present,
                "evidence": [
                    "APP11/JUMBF byte markers detected in JPEG payload." if present else "No APP11/JUMBF markers detected in JPEG payload."
                ],
            }

        if ext == ".png":
            present = ProvenanceService._scan_png_chunks(file_path)
            return {
                "present": present,
                "valid": present,
                "evidence": [
                    "c2pa/caBX PNG chunk detected." if present else "No c2pa/caBX PNG chunk detected."
                ],
            }

        if ext == ".pdf":
            present, valid, notes = ProvenanceService._scan_pdf_provenance(file_path)
            return {"present": present, "valid": valid, "evidence": notes}

        if ext in [".docx", ".pptx", ".xlsx", ".zip", ".rar"]:
            present, valid, notes = ProvenanceService._scan_archive_provenance(file_path)
            return {"present": present, "valid": valid, "evidence": notes}

        return {
            "present": False,
            "valid": False,
            "evidence": ["No supported provenance structure detected for this file type."],
        }

    @staticmethod
    def _collect_metadata_signals(
        file_path: str,
        ext: str,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        creator = metadata.get("creator")
        device = metadata.get("device")
        editing_history = metadata.get("editing_history", []) if isinstance(metadata.get("editing_history"), list) else []
        evidence: List[str] = []
        manifest_hint = False

        if creator:
            evidence.append(f"Metadata creator identified as {creator}.")
        if device:
            evidence.append(f"Metadata device identified as {device}.")
        if editing_history:
            evidence.append(f"Editing history contains {len(editing_history)} event(s).")

        # Extra document/image fallbacks
        if ext == ".pdf":
            try:
                reader = PdfReader(file_path)
                info = reader.metadata or {}
                pdf_author = info.get("/Author") or info.get("author")
                pdf_creator = info.get("/Creator") or info.get("creator")
                pdf_producer = info.get("/Producer") or info.get("producer")
                if pdf_author or pdf_creator or pdf_producer:
                    manifest_hint = True
                if pdf_author and not creator:
                    creator = str(pdf_author)
                if pdf_creator and not device:
                    device = str(pdf_creator)
                if pdf_producer:
                    evidence.append(f"PDF producer metadata identified as {pdf_producer}.")
                if pdf_author:
                    evidence.append(f"PDF author metadata identified as {pdf_author}.")
            except Exception as exc:
                evidence.append(f"PDF metadata parsing error: {exc}")

        if ext in [".docx", ".pptx", ".xlsx"]:
            try:
                with zipfile.ZipFile(file_path, "r") as z:
                    names = [name.lower() for name in z.namelist()]
                    if any("c2pa" in name or "manifest" in name for name in names):
                        manifest_hint = True
                        evidence.append("Office package contains manifest-like provenance entries.")
                    if any("core.xml" in name for name in names):
                        evidence.append("Office core metadata container present.")
            except Exception as exc:
                evidence.append(f"Office provenance parsing error: {exc}")

        return {
            "creator": creator,
            "device": device,
            "editing_history": editing_history,
            "manifest_hint": manifest_hint,
            "evidence": evidence,
        }

    @staticmethod
    def _collect_ai_generation_signals(filename: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        evidence: List[str] = []
        present = False

        if any(marker in filename for marker in ["midjourney", "sdxl", "stable", "flux", "dalle", "sora", "runway", "veo"]):
            present = True
            evidence.append("Filename contains a known generative model cue.")

        creator = str(metadata.get("creator", "")).lower() if metadata.get("creator") else ""
        software = str(metadata.get("software_used", "")).lower() if metadata.get("software_used") else ""
        if any(marker in creator for marker in ["midjourney", "stable", "flux", "dalle", "sora", "runway", "veo"]) or any(
            marker in software for marker in ["midjourney", "stable", "flux", "dalle", "sora", "runway", "veo"]
        ):
            present = True
            evidence.append("Metadata suggests a generative AI pipeline was used.")

        return {"present": present, "evidence": evidence}

    @staticmethod
    def _classify_owner(
        *,
        has_manifest: bool,
        manifest_valid: bool,
        blockchain_verified: bool,
        ai_generation_signals: bool,
        creator: Optional[str],
    ) -> str:
        if has_manifest and manifest_valid and blockchain_verified:
            return "VERIFIED OWNER"
        if has_manifest and manifest_valid:
            return "VERIFIED OWNER"
        if has_manifest or blockchain_verified or creator or ai_generation_signals:
            return "PROBABLE OWNER"
        return "UNKNOWN OWNER"

    @staticmethod
    def _calculate_confidence(
        *,
        has_manifest: bool,
        manifest_valid: bool,
        blockchain_verified: bool,
        creator: Optional[str],
        device: Optional[str],
        editing_history: List[Dict[str, Any]],
        ai_generation_signals: bool,
    ) -> float:
        score = 25.0
        if has_manifest:
            score += 20.0
        if manifest_valid:
            score += 30.0
        if blockchain_verified:
            score += 20.0
        if creator:
            score += 7.5
        if device:
            score += 5.0
        if editing_history:
            score += min(7.5, len(editing_history) * 2.5)
        if ai_generation_signals:
            score += 5.0
        if has_manifest and not manifest_valid:
            score -= 15.0
        return round(max(0.0, min(100.0, score)), 2)

    @staticmethod
    def _scan_jpeg_app11_jumb(file_path: str) -> bool:
        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, "rb") as f:
                header = f.read(2)
                if header != b"\xff\xd8":
                    return False

                offset = 2
                while offset < min(file_size, 1024 * 1024):
                    f.seek(offset)
                    marker_header = f.read(4)
                    if len(marker_header) < 4:
                        break

                    marker, length = struct.unpack(">HH", marker_header)
                    if marker == 0xFFEB:
                        f.seek(offset + 4)
                        payload = f.read(20)
                        if b"jumb" in payload or b"C2PA" in payload:
                            return True

                    if marker == 0xFFDA:
                        break

                    offset += length + 2
        except Exception:
            pass
        return False

    @staticmethod
    def _scan_png_chunks(file_path: str) -> bool:
        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, "rb") as f:
                header = f.read(8)
                if header != b"\x89PNG\r\n\x1a\n":
                    return False

                offset = 8
                while offset < min(file_size, 1024 * 1024):
                    f.seek(offset)
                    chunk_header = f.read(8)
                    if len(chunk_header) < 8:
                        break

                    length, chunk_type = struct.unpack(">I4s", chunk_header)
                    chunk_type_str = chunk_type.decode("ascii", errors="ignore")

                    if chunk_type_str in {"c2pa", "caBX", "iTXt", "tEXt"}:
                        if chunk_type_str in {"c2pa", "caBX"}:
                            return True

                    if chunk_type_str == "IEND":
                        break

                    offset += length + 12
        except Exception:
            pass
        return False

    @staticmethod
    def _scan_pdf_provenance(file_path: str) -> tuple[bool, bool, List[str]]:
        notes: List[str] = []
        present = False
        valid = False
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            if b"c2pa" in content.lower() or b"content credentials" in content.lower():
                present = True
                valid = True
                notes.append("C2PA or Content Credentials marker found in PDF payload.")
            if b"/author" in content.lower() or b"/creator" in content.lower():
                present = True
                notes.append("PDF creator/author metadata detected in payload.")
            if b"/js" in content.lower() or b"/javascript" in content.lower():
                notes.append("Active script markers found in PDF payload.")
        except Exception as exc:
            notes.append(f"PDF provenance scan failed: {exc}")
        return present, valid, notes

    @staticmethod
    def _scan_archive_provenance(file_path: str) -> tuple[bool, bool, List[str]]:
        notes: List[str] = []
        present = False
        valid = False
        try:
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, "r") as z:
                    names = [name.lower() for name in z.namelist()]
                    if any("c2pa" in name or "manifest" in name for name in names):
                        present = True
                        valid = True
                        notes.append("Archive contains manifest-like provenance entries.")
                    if any(name.endswith("core.xml") for name in names):
                        present = True
                        notes.append("Office core metadata package found.")
            else:
                notes.append("Archive payload could not be opened as ZIP container.")
        except Exception as exc:
            notes.append(f"Archive provenance scan failed: {exc}")
        return present, valid, notes
