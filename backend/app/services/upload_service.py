import os
import shutil
import zipfile
from typing import Dict, Any, Tuple, Optional
from app.config import settings
from app.services.hashing_service import HashingService
from sqlmodel import Session, select
from app.models.schemas import Evidence, Hashes, Upload

# Magic bytes dictionary for file integrity validation
MAGIC_BYTES = {
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "gif": [b"GIF87a", b"GIF89a"],
    "pdf": [b"%PDF"],
    "zip": [b"PK\x03\x04"],
    "docx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "apk": [b"PK\x03\x04"],
    "exe": [b"MZ"],
    "dll": [b"MZ"],
    "wav": [b"RIFF"],
    "webp": [b"RIFF"]
}

class UploadService:
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Normalize a user supplied filename so it cannot escape the upload root.
        """
        normalized = filename.replace("\\", "/")
        safe_name = os.path.basename(normalized).strip()
        if not safe_name:
            raise ValueError("Uploaded filename is empty after sanitization.")
        return safe_name

    @staticmethod
    def validate_file_basics(filename: str, size_bytes: int) -> Tuple[bool, str]:
        """
        Validates file size and extension based on configuration.
        """
        filename = UploadService.sanitize_filename(filename)

        # Extension Check
        ext = filename.split(".")[-1].lower() if "." in filename else ""
        if ext not in settings.ALLOWED_EXTENSIONS:
            return False, f"File extension '.{ext}' is not supported by the platform."

        # Size Check
        size_mb = size_bytes / (1024 * 1024)
        if size_mb > settings.MAX_FILE_SIZE_MB:
            return False, f"File size ({size_mb:.2f} MB) exceeds maximum allowed limit ({settings.MAX_FILE_SIZE_MB} MB)."

        return True, "Valid"

    @staticmethod
    def validate_magic_bytes(file_path: str, filename: str) -> bool:
        """
        Validates that the file's headers match its claimed file extension.
        """
        ext = filename.split(".")[-1].lower() if "." in filename else ""
        if ext not in MAGIC_BYTES:
            # If we don't have signature rules for this type, pass by default
            return True

        expected_signatures = MAGIC_BYTES[ext]
        try:
            with open(file_path, "rb") as f:
                # Read the first 16 bytes for checking headers
                header = f.read(16)
                
                for sig in expected_signatures:
                    if header.startswith(sig):
                        return True
            return False
        except Exception:
            return False

    @staticmethod
    def scan_for_malware(file_path: str) -> Tuple[bool, str]:
        """
        Malware prescan using YARA signature mocks and basic binary rules.
        """
        try:
            # Scan for high-risk binary indicators (e.g. EICAR test file, susp structures)
            with open(file_path, "rb") as f:
                content = f.read(4096)
                
                # Check for standard EICAR test signature
                if b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in content:
                    return False, "Malware Detected: EICAR Standard Antivirus Test File signature matches."

                # Forensics check for suspicious executable overlays in office files
                ext = file_path.split(".")[-1].lower() if "." in file_path else ""
                if ext in ["docx", "pdf", "xlsx", "pptx"]:
                    if b"This program cannot be run in DOS mode" in content or b"PE\x00\x00" in content:
                        return False, "Malware Detected: Embedded Executable code in non-executable document format (exploit indicator)."

                archive_check = UploadService._inspect_archive_safety(file_path, ext, content)
                if archive_check is not None:
                    return archive_check

            return True, "Clean"
        except Exception as e:
            return True, f"Scan bypassed due to error: {str(e)}"

    @staticmethod
    def _inspect_archive_safety(file_path: str, ext: str, content: bytes) -> Optional[Tuple[bool, str]]:
        """
        Inspect archive payloads for compression bombs and nested archive payloads.
        """
        if ext not in {"zip", "rar"}:
            if UploadService._looks_like_polyglot(content):
                return False, "Malware Detected: Polyglot payload contains multiple file-format signatures."
            return None

        if ext != "zip":
            return None

        try:
            if not zipfile.is_zipfile(file_path):
                return False, "Malware Detected: Archive file structure is malformed."

            with zipfile.ZipFile(file_path, "r") as archive:
                total_uncompressed = 0
                total_compressed = 0
                nested_zip_entries = 0

                for info in archive.infolist():
                    total_uncompressed += int(info.file_size or 0)
                    total_compressed += int(info.compress_size or 0)

                    name = info.filename.lower()
                    if name.endswith(".zip"):
                        nested_zip_entries += 1

                    if info.file_size > 0 and info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio >= 25.0:
                            return False, "Malware Detected: Archive compression ratio indicates a zip bomb."

                if nested_zip_entries > 0:
                    return False, "Malware Detected: Nested zip archive detected."

                if total_compressed > 0 and total_uncompressed / total_compressed >= 25.0:
                    return False, "Malware Detected: Archive compression ratio indicates a zip bomb."

                if total_uncompressed >= 250 * 1024 * 1024:
                    return False, "Malware Detected: Archive expands beyond safe extraction limits."

        except zipfile.BadZipFile:
            return False, "Malware Detected: Corrupted zip archive."
        except Exception as exc:
            return False, f"Malware Detected: Archive inspection failed ({exc})."

        return None

    @staticmethod
    def _looks_like_polyglot(content: bytes) -> bool:
        """
        Detect obvious polyglot payloads by looking for a secondary signature.
        """
        signatures = [
            b"%PDF",
            b"PK\x03\x04",
            b"MZ",
            b"RIFF",
            b"\x89PNG\r\n\x1a\n",
        ]
        seen = [sig for sig in signatures if sig in content[:8192]]
        return len(seen) >= 2 and not (
            seen[0] == b"RIFF" and b"WAVE" in content[:16]
        )

    @staticmethod
    def process_file_upload(
        db: Session,
        temp_file_path: str,
        filename: str,
        case_id: int,
        evidence_id: str
    ) -> Evidence:
        """
        Moves the uploaded file, runs validations, hashes it, checks duplicates, and saves everything.
        """
        # Calculate file size
        size_bytes = os.path.getsize(temp_file_path)
        filename = UploadService.sanitize_filename(filename)
        
        # Verify extensions/size
        valid, msg = UploadService.validate_file_basics(filename, size_bytes)
        if not valid:
            raise ValueError(msg)

        # Ensure storage directory exists
        dest_path = os.path.join(settings.UPLOAD_DIR, f"{evidence_id}_{filename}")
        if not os.path.abspath(dest_path).startswith(os.path.abspath(settings.UPLOAD_DIR)):
            raise ValueError("Unsafe upload path detected.")
        shutil.copy2(temp_file_path, dest_path)

        # Determine file type group
        ext = filename.split(".")[-1].lower() if "." in filename else ""
        file_type = "unknown"
        if ext in ["jpg", "jpeg", "png", "heic", "webp", "tiff"]:
            file_type = "image"
        elif ext in ["mp4", "mov", "avi", "mkv"]:
            file_type = "video"
        elif ext in ["mp3", "wav", "aac"]:
            file_type = "audio"
        elif ext in ["pdf", "docx", "pptx", "xlsx"]:
            file_type = "document"
        elif ext in ["zip", "rar"]:
            file_type = "archive"
        elif ext in ["exe", "dll", "apk"]:
            file_type = "executable"

        # 1. Integrity Validation (magic bytes check)
        integrity_valid = UploadService.validate_magic_bytes(dest_path, filename)

        # 2. Malware Scan
        malware_passed, malware_msg = UploadService.scan_for_malware(dest_path)

        # 3. Calculate Cryptographic & Perceptual Hashes
        md5_val, sha256_val, sha512_val = HashingService.calculate_crypto_hashes(dest_path)
        p_val, a_val, d_val = None, None, None
        video_sig, audio_sig = None, None

        if file_type == "image":
            p_val, a_val, d_val = HashingService.calculate_image_hashes(dest_path)
        elif file_type == "video":
            video_sig = HashingService.calculate_video_signatures(dest_path)
        elif file_type == "audio":
            audio_sig = HashingService.calculate_audio_signatures(dest_path)

        # 4. Duplicate Detection (check if database contains this hash)
        duplicate_check = db.exec(
            select(Hashes).where(Hashes.sha256 == sha256_val)
        ).first()
        duplicate_detected = duplicate_check is not None

        # 5. Determine base risk level based on validation failures
        risk_level = "LOW"
        if not integrity_valid or not malware_passed:
            risk_level = "CRITICAL"
        elif duplicate_detected:
            risk_level = "MEDIUM"

        # Determine mime type from extension
        mime_map = {
            "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "webp": "image/webp",
            "pdf": "application/pdf", "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "zip": "application/zip", "exe": "application/octet-stream", "apk": "application/vnd.android.package-archive"
        }
        mime_type = mime_map.get(ext, "application/octet-stream")

        # Save Evidence Record
        evidence = Evidence(
            id=evidence_id,
            case_id=case_id,
            filename=filename,
            file_type=file_type,
            mime_type=mime_type,
            size_bytes=size_bytes,
            status="ingested",
            risk_level=risk_level,
            trust_score=95.0 if integrity_valid and malware_passed else 10.0
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)

        # Save Upload Tracker
        upload_record = Upload(
            evidence_id=evidence_id,
            storage_path=dest_path,
            upload_status="completed",
            total_chunks=1,
            uploaded_chunks=1,
            integrity_valid=integrity_valid,
            malware_scan_passed=malware_passed,
            duplicate_detected=duplicate_detected
        )
        db.add(upload_record)

        # Save Hash Fingerprints
        hash_record = Hashes(
            evidence_id=evidence_id,
            md5=md5_val,
            sha256=sha256_val,
            sha512=sha512_val,
            p_hash=p_val,
            a_hash=a_val,
            d_hash=d_val,
            video_signatures=video_sig,
            audio_signatures=audio_sig
        )
        db.add(hash_record)
        db.commit()

        return evidence
