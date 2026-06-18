from __future__ import annotations

from pathlib import Path


def write_temp_file(tmp_path: Path, name: str, data: bytes) -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


def png_blob() -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"\x00" * 256


def pdf_blob(*, javascript: bool = False, manifest: bool = False) -> bytes:
    content = [
        b"%PDF-1.7\n",
        b"1 0 obj\n<< /Type /Catalog",
    ]
    if javascript:
        content.append(b" /OpenAction << /S /JavaScript /JS (app.alert('x')) >>")
    content.append(b" >>\nendobj\n")
    if manifest:
        content.append(b"2 0 obj\n<< /Type /Metadata /Subtype /XML >>\nendobj\n")
        content.append(b"c2pa content credentials\n")
    content.append(b"trailer\n<<>>\n%%EOF")
    return b"".join(content)


def wav_blob() -> bytes:
    return b"RIFF" + b"\x00" * 40 + b"WAVEfmt "


def auth_headers(client, email: str = "tester@deeptrace.ai", password: str = "testpassword") -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def upload_file(
    client,
    session,
    *,
    tmp_path: Path,
    filename: str,
    blob: bytes,
    mime_type: str,
    case_number: str = "CASE-2026-TEST",
):
    from sqlmodel import select
    from app.models.schemas import Case

    case = session.exec(select(Case).where(Case.case_number == case_number)).first()
    assert case is not None

    headers = auth_headers(client)
    local_name = Path(filename.replace("\\", "/")).name or "upload.bin"
    target = write_temp_file(tmp_path, local_name, blob)
    with target.open("rb") as fh:
        response = client.post(
            "/api/v1/upload",
            data={"case_id": case.id},
            files={"file": (filename, fh, mime_type)},
            headers=headers,
        )
    return response
