import os
import zipfile
from typing import Dict, Any, List, Tuple
from pypdf import PdfReader

class DocumentForensicsService:
    @staticmethod
    def analyze_document(file_path: str) -> Dict[str, Any]:
        """
        Runs forensic validation on documents (PDF or DOCX) to find hidden code or tampering.
        """
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == ".pdf":
            return DocumentForensicsService._analyze_pdf(file_path)
        elif ext in [".docx", ".xlsx", ".pptx"]:
            return DocumentForensicsService._analyze_docx(file_path)
            
        return {
            "tampered": False,
            "confidence": 100.0,
            "reasons": ["Unsupported document type for deep structural forensics"],
            "details": {}
        }

    @staticmethod
    def _analyze_pdf(file_path: str) -> Dict[str, Any]:
        """
        Performs PDF structural forensics (PDFID/PeePDF style scans).
        Detects JavaScript actions, launch commands, and incremental modification indicators.
        """
        tampered = False
        reasons = []
        confidence = 95.0
        
        details = {
            "javascript_count": 0,
            "js_count": 0,
            "open_action_count": 0,
            "launch_count": 0,
            "embedded_files_count": 0,
            "incremental_updates_count": 0
        }

        try:
            # 1. Binary stream scan for active triggers
            with open(file_path, "rb") as f:
                content = f.read()

                # Scan signatures
                details["javascript_count"] = content.count(b"/JavaScript")
                details["js_count"] = content.count(b"/JS")
                details["open_action_count"] = content.count(b"/OpenAction")
                details["launch_count"] = content.count(b"/Launch")
                details["embedded_files_count"] = content.count(b"/EmbeddedFiles")
                
                # Check for incremental updates (multiple %EOF markers)
                eof_count = content.count(b"%%EOF")
                details["incremental_updates_count"] = max(0, eof_count - 1)

            # 2. Risk evaluation
            if details["javascript_count"] > 0 or details["js_count"] > 0:
                tampered = True
                reasons.append(f"Embedded scripts found ({details['javascript_count']} /JavaScript, {details['js_count']} /JS objects)")
                confidence = 88.0

            if details["open_action_count"] > 0:
                tampered = True
                reasons.append("Auto-execute trigger found (/OpenAction action launches code on document opening)")
                confidence = 90.0

            if details["launch_count"] > 0:
                tampered = True
                reasons.append("Process launching command found (/Launch action can execute system binaries)")
                confidence = 92.0

            if details["incremental_updates_count"] > 0:
                # Incremental updates are often used to append invisible edited pages/text layers
                tampered = True
                reasons.append(f"Incremental edits detected: file has {details['incremental_updates_count']} appended revisions")
                confidence = 80.0

        except Exception as e:
            reasons.append(f"PDF structure scan failed: {str(e)}")
            confidence = 50.0

        if not reasons:
            reasons.append("No active script tags or incremental revision anomalies found in PDF structure")
            confidence = 95.0

        return {
            "tampered": tampered,
            "confidence": confidence,
            "reasons": reasons,
            "details": details,
            "verification_method": "PDFID/PeePDF-style structural audit + OOXML archive inspection",
            "supporting_evidence": reasons,
            "modified_regions": []
        }

    @staticmethod
    def _analyze_docx(file_path: str) -> Dict[str, Any]:
        """
        Audits Office Open XML templates (ZIP archive containing XML parts).
        Searches for embedded macro containers (vbaProject.bin).
        """
        tampered = False
        reasons = []
        confidence = 95.0
        
        details = {
            "has_macros": False,
            "macro_file": None,
            "embedded_objects": []
        }

        try:
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, "r") as z:
                    file_list = z.namelist()
                    
                    # Search for VBA macro binaries
                    vba_files = [f for f in file_list if "vbaProject.bin" in f or "vbaData.xml" in f]
                    if vba_files:
                        details["has_macros"] = True
                        details["macro_file"] = vba_files[0]
                        tampered = True
                        reasons.append(f"Active Macro container detected in OOXML package: {vba_files[0]} (Macro-phishing risk)")
                        confidence = 90.0
                        
                    # Check for external target triggers (CVE exploit indicators)
                    external_rels = [f for f in file_list if "_rels/" in f and f.endswith(".rels")]
                    for rel in external_rels:
                        rel_content = z.read(rel)
                        if b"TargetMode=\"External\"" in rel_content:
                            details["embedded_objects"].append(rel)
                            tampered = True
                            reasons.append(f"External reference payload found in relations link {rel} (templates injection indicator)")
                            confidence = 85.0
        except Exception as e:
            reasons.append(f"Office container audit failed: {str(e)}")
            confidence = 50.0

        if not reasons:
            reasons.append("No embedded macro binaries or template injection links found in OOXML archive")
            confidence = 95.0

        return {
            "tampered": tampered,
            "confidence": confidence,
            "reasons": reasons,
            "details": details
        }
