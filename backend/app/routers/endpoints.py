import os
import json
import uuid
import jwt
import hashlib
import secrets
import time
import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status, Request, Query
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, select
from pydantic import BaseModel
from fastapi.responses import StreamingResponse

from app.db import get_db
from app.config import settings
from app.models.schemas import (
    User, UserCreate, UserLogin, Token, Organization, Case, CaseCreate,
    Evidence, Upload, Hashes, MetadataRecord, AuditLog, BlockchainRecord, UserSession, DocumentTrace,
    EventLog, PasswordResetToken, ForgotPasswordRequest, ResetPasswordRequest,
    ProvenanceRecord, Report, ForensicsResult, DeepfakeResult, AIAttributionResult
)
from app.services.upload_service import UploadService
from app.services.metadata_service import MetadataService
from app.services.trust_service import TrustService
from app.services.hashing_service import HashingService
from app.services.image_forensics import ImageForensicsService
from app.services.video_forensics import VideoForensicsService
from app.services.audio_forensics import AudioForensicsService
from app.services.document_forensics import DocumentForensicsService
from app.services.provenance_service import ProvenanceService
from app.services.deepfake_service import DeepfakeService
from app.services.deepfake_assessment import DeepfakeAssessmentService
from app.services.ai_attribution_service import AIAttributionService
from app.services.blockchain_service import BlockchainService
from app.services.blockchain_assessment import BlockchainAssessmentService
from app.services.reporting_service import ReportingService
from app.services.forensics_summary import ForensicsSummaryService
from app.services.trust_assessment import TrustAssessmentService
from app.services.forensic_trace_service import ForensicTraceService
from app.services.event_service import EventService

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login", auto_error=False)

def issue_access_token(email: str, session_id: str) -> str:
    token_data = {
        "sub": email,
        "sid": session_id,
        "jti": str(uuid.uuid4()),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(token_data, settings.SECRET_KEY, algorithm="HS256")

def get_token_payload(token: str) -> Dict[str, str]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload if isinstance(payload, dict) else {}
    except jwt.PyJWTError:
        return {}

# Auth Helpers
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
        
    payload = get_token_payload(token)
    email: str = payload.get("sub")
    if email is None:
        raise credentials_exception
        
    user = db.exec(select(User).where(User.email == email)).first()
    if user is None:
        raise credentials_exception
    return user

def get_current_session_id(token: str = Depends(oauth2_scheme)) -> str:
    payload = get_token_payload(token or "")
    email = payload.get("sub")
    return payload.get("sid") or (f"legacy:{email}" if email else "legacy:unknown")

def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _generate_reset_token() -> tuple[str, str, datetime]:
    token = secrets.token_urlsafe(32)
    return token, _hash_reset_token(token), datetime.now(timezone.utc) + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)

def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)

def _send_reset_email(recipient: str, reset_link: str) -> None:
    if not settings.ENABLE_PASSWORD_RESET:
        raise HTTPException(status_code=503, detail="Password reset is disabled by configuration.")
    missing = [name for name, value in {
        "SMTP_HOST": settings.SMTP_HOST,
        "SMTP_USER": settings.SMTP_USER,
        "SMTP_PASSWORD": settings.SMTP_PASSWORD,
        "SMTP_FROM_EMAIL": settings.SMTP_FROM_EMAIL,
    }.items() if not value]
    if missing:
        raise HTTPException(status_code=503, detail=f"Password reset email is unavailable. Missing: {', '.join(missing)}")

    message = EmailMessage()
    message["Subject"] = "DeepTrace password reset"
    message["From"] = formataddr(("DeepTrace", settings.SMTP_FROM_EMAIL or settings.SMTP_USER or "noreply@localhost"))
    message["To"] = recipient
    message.set_content(
        "A password reset was requested for your DeepTrace account.\n\n"
        f"Reset link: {reset_link}\n\n"
        "If you did not request this change, you can ignore this message."
    )

    context = ssl.create_default_context()
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as smtp:
        smtp.starttls(context=context)
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        smtp.send_message(message)

# --- AUTH ENDPOINTS ---
@router.post("/auth/register", response_model=Token)
def register(user_in: UserCreate, db: Session = Depends(get_db), request: Request = None):
    # Create org if not exists
    org = db.exec(select(Organization).where(Organization.name == user_in.organization_name)).first()
    if not org:
        org = Organization(name=user_in.organization_name)
        db.add(org)
        db.commit()
        db.refresh(org)

    # Create user
    existing_user = db.exec(select(User).where(User.email == user_in.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already registered")

    hashed_pwd = HashingService.hash_password(user_in.password)
    user = User(
        email=user_in.email,
        hashed_password=hashed_pwd,
        full_name=user_in.full_name,
        role="analyst",
        organization_id=org.id
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    session_id = str(uuid.uuid4())
    session_trace = UserSession(
        session_id=session_id,
        user_id=user.id,
        user_email=user.email,
        user_agent=request.headers.get("user-agent") if request else None,
        ip_address=request.client.host if request and request.client else None,
    )
    db.add(session_trace)
    db.commit()

    token = issue_access_token(user.email, session_id)
    EventService.log(
        db,
        event_type="USER_REGISTERED",
        message=f"User registered: {user.email}",
        severity="INFO",
        source="auth",
        user_email=user.email,
        session_id=session_id,
        payload={"organization": org.name, "full_name": user.full_name},
    )
    return Token(access_token=token, token_type="bearer", session_id=session_id)

@router.post("/auth/login", response_model=Token)
def login(user_in: UserLogin, db: Session = Depends(get_db), request: Request = None):
    user = db.exec(select(User).where(User.email == user_in.email)).first()
    if not user or not HashingService.verify_password(user_in.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    session_id = str(uuid.uuid4())
    session_trace = UserSession(
        session_id=session_id,
        user_id=user.id,
        user_email=user.email,
        user_agent=request.headers.get("user-agent") if request else None,
        ip_address=request.client.host if request and request.client else None,
    )
    db.add(session_trace)
    db.commit()

    token = issue_access_token(user.email, session_id)
    EventService.log(
        db,
        event_type="LOGIN_SUCCESS",
        message=f"User logged in: {user.email}",
        severity="INFO",
        source="auth",
        user_email=user.email,
        session_id=session_id,
    )
    return Token(access_token=token, token_type="bearer", session_id=session_id)

@router.post("/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, request: Request = None, db: Session = Depends(get_db)):
    user = db.exec(select(User).where(User.email == payload.email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="No account found for the provided email.")

    token, token_hash, expires_at = _generate_reset_token()
    reset_token = PasswordResetToken(
        user_id=user.id,
        email=user.email,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(reset_token)
    db.commit()
    db.refresh(reset_token)

    reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    delivery_state = "not_configured"
    delivery_error = None
    try:
        _send_reset_email(user.email, reset_link)
        delivery_state = "sent"
    except HTTPException as exc:
        delivery_error = exc.detail
        if settings.ENABLE_PASSWORD_RESET:
            raise

    EventService.log(
        db,
        event_type="PASSWORD_RESET_REQUESTED",
        message=f"Password reset requested for {user.email}",
        severity="WARNING" if delivery_state != "sent" else "INFO",
        source="auth",
        user_email=user.email,
        payload={
            "delivery_state": delivery_state,
            "delivery_error": delivery_error,
            "expires_at": expires_at.isoformat(),
        },
    )
    return {
        "status": "success" if delivery_state == "sent" else "delivery_unavailable",
        "message": "Password reset email sent." if delivery_state == "sent" else "Password reset token generated but email delivery is unavailable.",
        "delivery_state": delivery_state,
        "reset_token": token if delivery_state != "sent" else None,
        "expires_at": expires_at.isoformat(),
    }

@router.post("/auth/reset-password")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")

    token_hash = _hash_reset_token(payload.token)
    reset_record = db.exec(select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)).first()
    if not reset_record:
        raise HTTPException(status_code=400, detail="Reset token is invalid.")
    if reset_record.used_at:
        raise HTTPException(status_code=400, detail="Reset token has already been used.")
    if _as_utc(reset_record.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Reset token has expired.")

    user = db.exec(select(User).where(User.id == reset_record.user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="Account not found.")

    user.hashed_password = HashingService.hash_password(payload.password)
    reset_record.used_at = datetime.now(timezone.utc)
    db.add(user)
    db.add(reset_record)
    db.commit()

    EventService.log(
        db,
        event_type="PASSWORD_RESET_COMPLETED",
        message=f"Password reset completed for {user.email}",
        severity="INFO",
        source="auth",
        user_email=user.email,
        payload={"reset_token_id": reset_record.id},
    )
    return {"status": "success", "message": "Password has been reset successfully."}

# --- CASES ENDPOINTS ---
@router.post("/cases", response_model=Case)
def create_case(case_in: CaseCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Generate sequential case number
    case_count = len(db.exec(select(Case)).all())
    case_num = f"CASE-{datetime.now(timezone.utc).year}-{case_count + 1:04d}"
    
    case = Case(
        case_number=case_num,
        title=case_in.title,
        description=case_in.description,
        creator_id=current_user.id
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    EventService.log(
        db,
        event_type="CASE_CREATED",
        message=f"Case created: {case.case_number}",
        severity="INFO",
        source="cases",
        user_email=current_user.email,
        case_id=case.id,
        payload={"title": case.title, "status": case.status},
    )
    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "creator_id": case.creator_id,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
    }

@router.get("/cases", response_model=List[Case])
def get_cases(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.exec(select(Case)).all()

# --- UPLOAD & INGESTION ENGINE ---
@router.post("/upload")
async def upload_evidence(
    case_id: int = Form(...),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    session_id: str = Depends(get_current_session_id),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    POST /upload
    Handles file upload, stores the file, validates structure/magic bytes,
    performs cryptographic hashes, and updates DB.
    """
    # Verify case exists
    case = db.exec(select(Case).where(Case.id == case_id)).first()
    if not case:
        raise HTTPException(status_code=404, detail="Target case not found")

    evidence_id = str(uuid.uuid4())
    safe_filename = UploadService.sanitize_filename(file.filename)
    
    # Save the file to a temporary location
    temp_dir = os.path.join(settings.UPLOAD_DIR, "temp")
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, f"{evidence_id}_{safe_filename}")
    
    try:
        with open(temp_path, "wb") as f:
            shutil_f = file.file
            # Standard chunk write
            while chunk := shutil_f.read(8192):
                f.write(chunk)
                
        # Process ingestion through UploadService
        evidence = UploadService.process_file_upload(
            db=db,
            temp_file_path=temp_path,
            filename=file.filename,
            case_id=case_id,
            evidence_id=evidence_id
        )
        
        # Log to Chain of Custody (AuditLog)
        upload_rec = db.exec(select(Upload).where(Upload.evidence_id == evidence.id)).first()
        hashes_rec = db.exec(select(Hashes).where(Hashes.evidence_id == evidence.id)).first()
        
        audit_log = AuditLog(
            evidence_id=evidence.id,
            actor=current_user.email,
            operation="Upload & Ingestion",
            hash_value=hashes_rec.sha256 if hashes_rec else "unknown",
            result="Success" if upload_rec and upload_rec.integrity_valid else "Warning: Integrity check failed"
        )
        db.add(audit_log)
        db.commit()

        upload_rec = db.exec(select(Upload).where(Upload.evidence_id == evidence.id)).first()
        metadata_rec = db.exec(select(MetadataRecord).where(MetadataRecord.evidence_id == evidence.id)).first()
        trace = ForensicTraceService.create_upload_trace(
            db,
            session_id=session_id,
            user=current_user,
            evidence=evidence,
            upload=upload_rec,
            metadata=metadata_rec,
            raw_metadata=metadata_rec.raw_metadata if metadata_rec else {},
        )
        EventService.log(
            db,
            event_type="EVIDENCE_UPLOADED",
            message=f"Evidence uploaded: {evidence.filename}",
            severity="INFO" if upload_rec and upload_rec.integrity_valid else "WARNING",
            source="upload",
            user_email=current_user.email,
            session_id=session_id,
            case_id=case_id,
            evidence_id=evidence.id,
            payload={
                "filename": evidence.filename,
                "risk_level": evidence.risk_level,
                "trust_score": evidence.trust_score,
                "integrity_valid": upload_rec.integrity_valid if upload_rec else None,
            },
        )

        return {
            "status": "success",
            "evidence_id": evidence.id,
            "filename": evidence.filename,
            "risk_level": evidence.risk_level,
            "trust_score": evidence.trust_score
            ,"session_id": session_id,
            "trace_id": trace.id,
        }

    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload processing failed: {str(e)}")
    finally:
        # Cleanup temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)

# --- ANALYSIS ENDPOINT ---
@router.post("/analyze")
def analyze_evidence(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    session_id: str = Depends(get_current_session_id),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    POST /analyze
    Initiates deep analysis pipeline: metadata parsing, deep forensics scanning, C2PA provenance extraction, and trust scoring.
    """
    evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    upload_rec = db.exec(select(Upload).where(Upload.evidence_id == evidence_id)).first()
    if not upload_rec:
        raise HTTPException(status_code=400, detail="Evidence files not uploaded properly")

    evidence.status = "analyzing"
    db.add(evidence)
    db.commit()

    analysis_start = time.perf_counter()
    analysis_errors: List[str] = []
    analysis_warnings: List[str] = []

    try:
        # 1. Extract Metadata
        meta_dict = MetadataService.extract_metadata(upload_rec.storage_path, evidence.file_type)
        forensics_summary = ForensicsSummaryService.build_from_service_result(
            evidence.file_type,
            {"tampered": False, "confidence": 0.0, "supporting_evidence": []},
        )
        
        # Check if record already exists, if so delete/overwrite
        existing_meta = db.exec(select(MetadataRecord).where(MetadataRecord.evidence_id == evidence_id)).first()
        if existing_meta:
            db.delete(existing_meta)
            db.commit()

        metadata_record = MetadataRecord(
            evidence_id=evidence_id,
            creator=meta_dict.get("creator"),
            software_used=meta_dict.get("software_used"),
            created_datetime=meta_dict.get("created_datetime"),
            modified_datetime=meta_dict.get("modified_datetime"),
            gps_latitude=meta_dict.get("gps_latitude"),
            gps_longitude=meta_dict.get("gps_longitude"),
            raw_metadata=meta_dict.get("raw_metadata", {})
        )
        db.add(metadata_record)
        db.commit()

        # 2. Clear pre-existing forensic results if re-running
        old_forensics = db.exec(select(ForensicsResult).where(ForensicsResult.evidence_id == evidence_id)).all()
        for f in old_forensics:
            db.delete(f)
        db.commit()

        # 3. Run Forensics Engine based on file type
        if evidence.file_type == "image":
            img_results = ImageForensicsService.run_all_analyses(
                upload_rec.storage_path, evidence_id, settings.UPLOAD_DIR
            )
            forensics_summary = ForensicsSummaryService.build_from_service_result("image", img_results)
            for sub_engine, res in img_results["details"].items():
                db.add(ForensicsResult(
                    evidence_id=evidence_id,
                    engine_name=f"Image {sub_engine.upper()}",
                    tampered=res["tampered"],
                    confidence=res["confidence"],
                    output_details=res
                ))
        elif evidence.file_type == "video":
            v_res = VideoForensicsService.analyze_video(upload_rec.storage_path)
            forensics_summary = ForensicsSummaryService.build_from_service_result("video", v_res)
            db.add(ForensicsResult(
                evidence_id=evidence_id,
                engine_name="Video Structural Forensics",
                tampered=v_res["tampered"],
                confidence=v_res["confidence"],
                output_details=v_res["forensics_findings"]
            ))
        elif evidence.file_type == "audio":
            a_res = AudioForensicsService.analyze_audio(upload_rec.storage_path)
            forensics_summary = ForensicsSummaryService.build_from_service_result("audio", a_res)
            db.add(ForensicsResult(
                evidence_id=evidence_id,
                engine_name="Audio Spectrogram Forensics",
                tampered=a_res["tampered"],
                confidence=a_res["deepfake_probability"] * 100.0,
                output_details={"reasons": a_res["reasons"], "authenticity_score": a_res["authenticity_score"], "stats": a_res["stats"]}
            ))
        elif evidence.file_type == "document":
            d_res = DocumentForensicsService.analyze_document(upload_rec.storage_path)
            forensics_summary = ForensicsSummaryService.build_from_service_result("document", d_res)
            db.add(ForensicsResult(
                evidence_id=evidence_id,
                engine_name="Document Structural Forensics",
                tampered=d_res["tampered"],
                confidence=d_res["confidence"],
                output_details={"reasons": d_res["reasons"], "structure": d_res["details"]}
            ))
        
        db.commit()

        # 4. Extract Provenance (C2PA Content Credentials)
        prov_assessment = ProvenanceService.assess_provenance(
            upload_rec.storage_path,
            metadata={
                "creator": meta_dict.get("creator"),
                "device": None,
                "editing_history": [],
                "software_used": meta_dict.get("software_used"),
            },
        )

        # Clear old provenance records
        old_prov = db.exec(select(ProvenanceRecord).where(ProvenanceRecord.evidence_id == evidence_id)).all()
        for p in old_prov:
            db.delete(p)
        db.commit()

        provenance_rec = ProvenanceRecord(
            evidence_id=evidence_id,
            has_manifest=prov_assessment["has_manifest"],
            manifest_valid=prov_assessment["manifest_valid"],
            creator=prov_assessment["creator"],
            device=prov_assessment["device"],
            editing_history=prov_assessment["editing_history"],
            verification_method=prov_assessment["verification_method"]
        )
        db.add(provenance_rec)
        db.commit()

        # 5. Run Deepfake Detection
        # Clear old deepfake results
        old_deepfake = db.exec(select(DeepfakeResult).where(DeepfakeResult.evidence_id == evidence_id)).all()
        for df_res in old_deepfake:
            db.delete(df_res)
        db.commit()

        df_data = DeepfakeService.detect_deepfake(upload_rec.storage_path, evidence.file_type, evidence_id, settings.UPLOAD_DIR)
        deepfake_assessment = DeepfakeAssessmentService.build(evidence.file_type, df_data)
        db.add(DeepfakeResult(
            evidence_id=evidence_id,
            model_name=df_data["model_name"],
            deepfake_probability=df_data["deepfake_probability"],
            confidence=df_data["confidence"],
            heatmap_path=df_data["heatmap_path"],
            explainability=df_data["explainability"]
        ))
        db.commit()

        # 6. Run AI Content Attribution
        # Clear old attribution results
        old_ai_attr = db.exec(select(AIAttributionResult).where(AIAttributionResult.evidence_id == evidence_id)).all()
        for attr_res in old_ai_attr:
            db.delete(attr_res)
        db.commit()

        ai_data = AIAttributionService.attribute_ai_content(upload_rec.storage_path, evidence.file_type)
        db.add(AIAttributionResult(
            evidence_id=evidence_id,
            predicted_source=ai_data["predicted_source"],
            probability=ai_data["probability"],
            confidence=ai_data["confidence"],
            indicators=ai_data["indicators"]
        ))
        db.commit()

        # 7. Update dynamic Trust Score & Risk levels evaluating forensics, C2PA credentials, deepfakes & AI attribution
        TrustService.calculate_score(db, evidence_id)

        evidence.status = "completed"
        db.add(evidence)

        # Log to Chain of Custody (AuditLog)
        hash_rec = db.exec(select(Hashes).where(Hashes.evidence_id == evidence_id)).first()
        audit_log = AuditLog(
            evidence_id=evidence_id,
            actor=current_user.email,
            operation="Deep Forensic Analysis",
            hash_value=hash_rec.sha256 if hash_rec else "unknown",
            result="Success"
        )
        db.add(audit_log)
        db.commit()
        trust_assessment = TrustAssessmentService.build(db, evidence_id)
        audit_logs = db.exec(select(AuditLog).where(AuditLog.evidence_id == evidence_id).order_by(AuditLog.timestamp)).all()
        trace = db.exec(select(DocumentTrace).where(DocumentTrace.evidence_id == evidence_id)).first()
        if trace:
            ai_attribution_record = db.exec(
                select(AIAttributionResult).where(AIAttributionResult.evidence_id == evidence_id)
            ).first()
            ForensicTraceService.update_analysis_trace(
                db,
                trace=trace,
                evidence=evidence,
                metadata=metadata_record,
                forensics_summary=forensics_summary,
                provenance_assessment=prov_assessment,
                deepfake_assessment=deepfake_assessment,
                ai_attribution=ai_attribution_record,
                blockchain_assessment=trust_assessment.get("blockchain_assessment", {}),
                claim_assessment=trust_assessment.get("claim_assessment", {}),
                trust_assessment=trust_assessment,
                analysis_steps=[
                    {"stage": "metadata", "status": "completed", "summary": meta_dict.get("creator")},
                    {"stage": "forensics", "status": "completed", "summary": forensics_summary.get("verification_method")},
                    {"stage": "provenance", "status": "completed", "summary": prov_assessment.get("verification_method")},
                    {"stage": "deepfake", "status": "completed", "summary": deepfake_assessment.get("verification_method")},
                    {"stage": "ai_attribution", "status": "completed", "summary": ai_data["predicted_source"]},
                    {"stage": "trust", "status": "completed", "summary": trust_assessment.get("risk_level")},
                ],
                duration_ms=(time.perf_counter() - analysis_start) * 1000.0,
                warnings=analysis_warnings,
                errors=analysis_errors,
            )
        EventService.log(
            db,
            event_type="ANALYSIS_COMPLETED",
            message=f"Analysis completed for {evidence_id}",
            severity="INFO",
            source="analysis",
            user_email=current_user.email,
            session_id=session_id,
            case_id=evidence.case_id,
            evidence_id=evidence_id,
            payload={"trust_score": evidence.trust_score, "risk_level": evidence.risk_level},
        )

        return {
            "status": "completed",
            "evidence_id": evidence_id,
            "forensics_summary": forensics_summary,
            "provenance_assessment": prov_assessment,
            "deepfake_assessment": deepfake_assessment,
            "trust_assessment": trust_assessment,
            "claim_assessment": trust_assessment.get("claim_assessment"),
            "audit_logs": audit_logs,
            "trace_id": trace.id if trace else None,
        }

    except Exception as e:
        analysis_errors.append(str(e))
        evidence.status = "failed"
        db.add(evidence)
        db.commit()
        raise HTTPException(status_code=500, detail=f"Forensic analysis pipeline failed: {str(e)}")

# --- RETRIEVAL ENDPOINTS ---
@router.get("/analysis/{evidence_id}")
def get_analysis_results(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    GET /analysis/{id}
    Retrieves the complete state of investigation.
    """
    evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    hashes = db.exec(select(Hashes).where(Hashes.evidence_id == evidence_id)).first()
    metadata_record = db.exec(select(MetadataRecord).where(MetadataRecord.evidence_id == evidence_id)).first()
    upload = db.exec(select(Upload).where(Upload.evidence_id == evidence_id)).first()
    forensics = db.exec(select(ForensicsResult).where(ForensicsResult.evidence_id == evidence_id)).all()
    provenance = db.exec(select(ProvenanceRecord).where(ProvenanceRecord.evidence_id == evidence_id)).first()
    deepfake = db.exec(select(DeepfakeResult).where(DeepfakeResult.evidence_id == evidence_id)).first()
    ai_attribution = db.exec(select(AIAttributionResult).where(AIAttributionResult.evidence_id == evidence_id)).first()
    blockchain = db.exec(select(BlockchainRecord).where(BlockchainRecord.evidence_id == evidence_id)).first()
    forensics_summary = ForensicsSummaryService.build_from_records(evidence.file_type, forensics)
    deepfake_assessment = DeepfakeAssessmentService.build_from_record(evidence.file_type, deepfake)
    provenance_assessment = None
    if provenance:
        provenance_assessment = ProvenanceService.assess_provenance(
            upload.storage_path if upload else "",
            metadata={
                "creator": provenance.creator,
                "device": provenance.device,
                "editing_history": provenance.editing_history,
                "software_used": metadata_record.software_used if metadata_record else None,
            },
            blockchain_verified=bool(blockchain),
        )
    trust_assessment = TrustAssessmentService.build(db, evidence_id)
    audit_logs = db.exec(select(AuditLog).where(AuditLog.evidence_id == evidence_id).order_by(AuditLog.timestamp)).all()

    return {
        "evidence": evidence,
        "upload": upload,
        "hashes": hashes,
        "metadata": metadata_record,
        "forensics": forensics,
        "forensics_summary": forensics_summary,
        "provenance": provenance,
        "provenance_assessment": provenance_assessment,
        "deepfake": deepfake,
        "deepfake_assessment": deepfake_assessment,
        "ai_attribution": ai_attribution,
        "blockchain": blockchain,
        "blockchain_assessment": BlockchainAssessmentService.build(
            blockchain,
            evidence_hash=hashes.sha256 if hashes else None,
            provenance_assessment=provenance_assessment,
            trust_score=evidence.trust_score,
        ),
        "claim_assessment": trust_assessment.get("claim_assessment"),
        "audit_logs": audit_logs,
        "trust_assessment": trust_assessment,
    }

@router.get("/timeline/{evidence_id}", response_model=List[AuditLog])
def get_timeline(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    GET /timeline/{id}
    Chain of Custody tracking history.
    """
    logs = db.exec(select(AuditLog).where(AuditLog.evidence_id == evidence_id).order_by(AuditLog.timestamp)).all()
    return logs

# --- VERIFICATION ENDPOINTS ---
class HashVerifyPayload(BaseModel):
    sha256: str

@router.post("/verify-hash")
def verify_hash(
    payload: HashVerifyPayload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    POST /verify-hash
    Queries the hash database for matching identities or variations (perceptual similarity).
    """
    match = db.exec(select(Hashes).where(Hashes.sha256 == payload.sha256)).first()
    if match:
        evidence = db.exec(select(Evidence).where(Evidence.id == match.evidence_id)).first()
        return {
            "match_found": True,
            "match_type": "Identical Match (Cryptographic SHA256)",
            "evidence": evidence
        }
        
    return {
        "match_found": False,
        "match_type": None,
        "evidence": None
    }

@router.post("/verify-c2pa")
def verify_c2pa(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    POST /verify-c2pa
    Extracts, decodes and validates C2PA Content Credentials directly from storage.
    """
    evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    upload_rec = db.exec(select(Upload).where(Upload.evidence_id == evidence_id)).first()
    if not upload_rec:
        raise HTTPException(status_code=400, detail="Evidence files not uploaded properly")

    # Run direct C2PA extractor
    existing_blockchain = db.exec(select(BlockchainRecord).where(BlockchainRecord.evidence_id == evidence_id)).first()
    prov_dict = ProvenanceService.assess_provenance(
        upload_rec.storage_path,
        blockchain_verified=bool(existing_blockchain),
    )

    # Clear old records
    old_prov = db.exec(select(ProvenanceRecord).where(ProvenanceRecord.evidence_id == evidence_id)).all()
    for p in old_prov:
        db.delete(p)
    db.commit()

    record = ProvenanceRecord(
        evidence_id=evidence_id,
        has_manifest=prov_dict["has_manifest"],
        manifest_valid=prov_dict["manifest_valid"],
        creator=prov_dict["creator"],
        device=prov_dict["device"],
        editing_history=prov_dict["editing_history"],
        verification_method=prov_dict["verification_method"]
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    EventService.log(
        db,
        event_type="PROVENANCE_VERIFIED",
        message=f"Provenance verified for {evidence_id}",
        severity="INFO" if prov_dict["verification_status"] == "VERIFIED OWNER" else "WARNING",
        source="provenance",
        user_email=current_user.email,
        evidence_id=evidence_id,
        payload={"verification_status": prov_dict["verification_status"]},
    )

    return {
        "id": record.id,
        "evidence_id": record.evidence_id,
        "has_manifest": record.has_manifest,
        "manifest_valid": record.manifest_valid,
        "creator": record.creator,
        "device": record.device,
        "editing_history": record.editing_history,
        "verification_method": record.verification_method,
        "verification_status": prov_dict["verification_status"],
        "ownership_classification": prov_dict["ownership_classification"],
        "confidence_score": prov_dict["confidence_score"],
        "supporting_evidence": prov_dict["supporting_evidence"],
        "reasons": prov_dict["reasons"]
    }

@router.get("/trust-score/{evidence_id}")
def get_trust_score(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    GET /trust-score/{id}
    Retrieves the structured trust intelligence assessment.
    """
    evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return TrustAssessmentService.build(db, evidence_id)

from fastapi.responses import FileResponse

@router.get("/report/{evidence_id}")
def get_forensic_report(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    GET /report/{id}
    Builds, signs, and streams a forensic report PDF.
    """
    evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    report_id = str(uuid.uuid4())
    report_filename = f"report_{evidence_id}.pdf"
    report_path = os.path.join(settings.REPORT_DIR, report_filename)
    
    # Generate the actual PDF report via ReportingService
    success = ReportingService.generate_pdf_report(db, evidence_id, report_path)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to generate PDF report")

    # Save metadata record of report to database
    report = Report(
        id=report_id,
        evidence_id=evidence_id,
        generated_by="System Forensic Analyst",
        storage_path=report_path,
        digital_signature=hashlib.sha256(f"{evidence_id}-signed-by-deeptrace".encode()).hexdigest(),
        trust_score_snapshot=evidence.trust_score,
        risk_level_snapshot=evidence.risk_level
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    EventService.log(
        db,
        event_type="REPORT_GENERATED",
        message=f"Report generated for {evidence_id}",
        severity="INFO",
        source="report",
        user_email=current_user.email,
        evidence_id=evidence_id,
        payload={"report_id": report.id, "filename": report_filename},
    )

    # Return the PDF file as a downloadable attachment
    return FileResponse(
        path=report_path,
        filename=report_filename,
        media_type="application/pdf"
    )

@router.post("/blockchain/register")
def register_on_blockchain(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    POST /blockchain/register
    Anchors evidence to simulated blockchain ledger, logs transaction receipts,
    updates Chain of Custody, and triggers trust score recalculation.
    """
    evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence item not found")

    record = BlockchainService.register_evidence(db, evidence_id, current_user.email)
    if not record:
        raise HTTPException(status_code=500, detail="Failed to anchor evidence on blockchain")

    # Recalculate Trust Score (so blockchain boost applies immediately)
    TrustService.calculate_score(db, evidence_id)

    evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
    hashes = db.exec(select(Hashes).where(Hashes.evidence_id == evidence_id)).first()
    provenance = db.exec(select(ProvenanceRecord).where(ProvenanceRecord.evidence_id == evidence_id)).first()
    upload = db.exec(select(Upload).where(Upload.evidence_id == evidence_id)).first()
    provenance_assessment = None
    if provenance and upload:
        provenance_assessment = ProvenanceService.assess_provenance(
            upload.storage_path,
            metadata={
                "creator": provenance.creator,
                "device": provenance.device,
                "editing_history": provenance.editing_history,
            },
            blockchain_verified=True,
        )
    blockchain_assessment = BlockchainAssessmentService.build(
        record,
        evidence_hash=hashes.sha256 if hashes else None,
        provenance_assessment=provenance_assessment,
        trust_score=evidence.trust_score if evidence else None,
    )
    trust_assessment = TrustAssessmentService.build(db, evidence_id)
    EventService.log(
        db,
        event_type="BLOCKCHAIN_REGISTERED",
        message=f"Blockchain registration completed for {evidence_id}",
        severity="INFO",
        source="blockchain",
        user_email=current_user.email,
        evidence_id=evidence_id,
        payload={"block_number": record.block_number, "transaction_hash": record.transaction_hash},
    )

    # Return dictionary to avoid detached session/lazy-loading issues
    return {
        "id": record.id,
        "evidence_id": record.evidence_id,
        "chain_name": record.chain_name,
        "transaction_hash": record.transaction_hash,
        "block_number": record.block_number,
        "registered_owner": record.registered_owner,
        "verification_status": record.verification_status,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "blockchain_assessment": blockchain_assessment,
        "trust_assessment": trust_assessment,
    }


@router.get("/verify-ledger/{evidence_id}")
def verify_ledger(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    GET /verify-ledger/{id}
    Returns a normalized blockchain custody assessment for the evidence item.
    """
    evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    record = db.exec(select(BlockchainRecord).where(BlockchainRecord.evidence_id == evidence_id)).first()
    hashes = db.exec(select(Hashes).where(Hashes.evidence_id == evidence_id)).first()
    provenance = db.exec(select(ProvenanceRecord).where(ProvenanceRecord.evidence_id == evidence_id)).first()
    upload = db.exec(select(Upload).where(Upload.evidence_id == evidence_id)).first()
    provenance_assessment = None
    if provenance and upload:
        provenance_assessment = ProvenanceService.assess_provenance(
            upload.storage_path,
            metadata={
                "creator": provenance.creator,
                "device": provenance.device,
                "editing_history": provenance.editing_history,
            },
            blockchain_verified=bool(record),
        )

    assessment = BlockchainAssessmentService.build(
        record,
        evidence_hash=hashes.sha256 if hashes else None,
        provenance_assessment=provenance_assessment,
        trust_score=evidence.trust_score if evidence else None,
    )

    EventService.log(
        db,
        event_type="BLOCKCHAIN_VERIFIED",
        message=f"Ledger verification completed for {evidence_id}",
        severity="INFO" if assessment.get("anchored") else "WARNING",
        source="blockchain",
        user_email=current_user.email,
        evidence_id=evidence_id,
        payload=assessment,
    )

    return assessment

@router.get("/events")
def get_events(
    current_user: User = Depends(get_current_user),
    since_id: Optional[int] = Query(default=None, ge=1),
    limit: int = Query(default=250, ge=1, le=500),
    db: Session = Depends(get_db),
):
    events = EventService.recent(db, since_id=since_id, limit=limit)
    return [
        {
            "id": event.id,
            "created_at": event.created_at.isoformat() if event.created_at else None,
            "severity": event.severity,
            "event_type": event.event_type,
            "message": event.message,
            "source": event.source,
            "user_email": event.user_email,
            "session_id": event.session_id,
            "case_id": event.case_id,
            "evidence_id": event.evidence_id,
            "payload": event.payload,
        }
        for event in events
    ]

@router.get("/events/stream")
def stream_events(
    token: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication token for event stream")

    payload = get_token_payload(token)
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    user = db.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    async def event_generator():
        last_id = 0
        while True:
            events = EventService.recent(db, since_id=last_id, limit=100)
            if events:
                for event in events:
                    last_id = max(last_id, event.id or last_id)
                    payload = {
                        "id": event.id,
                        "created_at": event.created_at.isoformat() if event.created_at else None,
                        "severity": event.severity,
                        "event_type": event.event_type,
                        "message": event.message,
                        "source": event.source,
                        "user_email": event.user_email,
                        "session_id": event.session_id,
                        "case_id": event.case_id,
                        "evidence_id": event.evidence_id,
                        "payload": event.payload,
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(1.0)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
