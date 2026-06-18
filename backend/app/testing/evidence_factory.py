from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class EvidenceCase:
    """Describe a synthetic evidence fixture."""

    kind: str
    file_type: str
    adversarial: bool
    polyglot: bool = False


def sanitize_filename(raw_name: str) -> str:
    """Strip any path traversal components and return a safe file name."""
    normalized = raw_name.replace("\\", "/")
    return Path(normalized).name


def build_evidence_blob(case: EvidenceCase) -> bytes:
    """Build a deterministic synthetic evidence payload for tests."""
    kind = case.kind.lower()
    file_type = case.file_type.lower()

    if kind == "image" and file_type == "png":
        if case.adversarial:
            return b"PNG_CORRUPT" + b"\x00" * 64
        return (
            b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\rIHDR"
            b"\x00\x00\x00\x10\x00\x00\x00\x10"
            b"\x08\x02\x00\x00\x00"
            b"\x90wS\xde"
            b"\x00\x00\x00\x0cIDAT"
            b"synthetic-image-data"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )

    if kind == "document" and file_type == "pdf":
        payload = (
            b"%PDF-1.7\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Count 0 /Kids [] /Type /Pages >>\nendobj\n"
            b"trailer\n<< /Root 1 0 R >>\n%%EOF"
        )
        if case.adversarial:
            payload += b"\n<< /OpenAction << /S /JavaScript /JS (app.alert('x')) >> >>"
        if case.polyglot:
            payload += b"\nPK\x03\x04synthetic-zip-overlay"
        return payload

    if kind == "audio" and file_type == "wav":
        if case.adversarial:
            return b"RIFF" + b"\x00" * 4 + b"BADWAVE" + b"\x00" * 32
        return (
            b"RIFF"
            b"\x24\x00\x00\x00"
            b"WAVE"
            b"fmt "
            b"\x10\x00\x00\x00"
            b"\x01\x00\x01\x00"
            b"\x44\xac\x00\x00"
            b"\x88\x58\x01\x00"
            b"\x02\x00\x10\x00"
            b"data"
            b"\x00\x00\x00\x00"
        )

    if kind == "archive" and file_type == "zip":
        return b"PK\x03\x04synthetic-archive"

    if kind == "executive" or kind == "executable":
        return b"MZ" + b"\x00" * 64

    raise ValueError(f"Unsupported evidence case: kind={case.kind!r}, file_type={case.file_type!r}")


def write_evidence_file(directory: Path, raw_name: str, blob: bytes) -> Path:
    """Write a synthetic evidence blob under a controlled directory."""
    directory.mkdir(parents=True, exist_ok=True)
    safe_name = sanitize_filename(raw_name)
    target_path = directory / safe_name
    target_path.write_bytes(blob)
    return target_path


def build_zip_bomb_blob(*, member_name: str = "payload.txt", payload_size: int = 1024 * 1024) -> bytes:
    """Build a highly compressible archive suitable for zip-bomb detection tests."""
    buffer = io.BytesIO()
    payload = b"A" * payload_size
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member_name, payload)
    return buffer.getvalue()


def build_nested_zip_blob() -> bytes:
    """Build a zip archive that contains another zip archive."""
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w", compression=zipfile.ZIP_DEFLATED) as inner:
        inner.writestr("inner.txt", b"nested archive marker")

    outer_buffer = io.BytesIO()
    with zipfile.ZipFile(outer_buffer, "w", compression=zipfile.ZIP_DEFLATED) as outer:
        outer.writestr("nested.zip", inner_buffer.getvalue())
    return outer_buffer.getvalue()


def build_polyglot_blob(primary: bytes, secondary: bytes) -> bytes:
    """Create a simple polyglot-style byte sequence for adversarial tests."""
    return primary + b"\n" + secondary + b"\npolyglot-marker"
