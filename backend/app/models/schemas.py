from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, JSON
from pydantic import BaseModel

from app.utils.time import utc_now

# 1. Organizations
class Organization(SQLModel, table=True):
    __tablename__ = "organizations"
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    users: List["User"] = Relationship(back_populates="organization")

# 2. Users
class User(SQLModel, table=True):
    __tablename__ = "users"
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    full_name: str
    role: str = Field(default="analyst")  # admin, analyst, supervisor
    is_active: bool = Field(default=True)
    mfa_enabled: bool = Field(default=False)
    organization_id: Optional[int] = Field(default=None, foreign_key="organizations.id")
    created_at: datetime = Field(default_factory=utc_now)

    organization: Optional[Organization] = Relationship(back_populates="users")
    cases: List["Case"] = Relationship(back_populates="creator")

# 3. Cases
class Case(SQLModel, table=True):
    __tablename__ = "cases"
    id: Optional[int] = Field(default=None, primary_key=True)
    case_number: str = Field(unique=True, index=True)
    title: str = Field(index=True)
    description: Optional[str] = None
    status: str = Field(default="active")  # active, closed, archived
    creator_id: Optional[int] = Field(default=None, foreign_key="users.id")
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    creator: Optional[User] = Relationship(back_populates="cases")
    evidence: List["Evidence"] = Relationship(back_populates="case")

# 4. Evidence
class Evidence(SQLModel, table=True):
    __tablename__ = "evidence"
    id: Optional[str] = Field(default=None, primary_key=True)  # UUID or unique identifier
    case_id: int = Field(foreign_key="cases.id")
    filename: str = Field(index=True)
    file_type: str = Field(index=True)  # image, video, audio, document, archive, executable
    mime_type: str
    size_bytes: int
    status: str = Field(default="ingested")  # ingested, analyzing, completed, failed
    risk_level: str = Field(default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    trust_score: float = Field(default=100.0)
    created_at: datetime = Field(default_factory=utc_now)

    case: Optional[Case] = Relationship(back_populates="evidence")
    upload: Optional["Upload"] = Relationship(back_populates="evidence")
    hashes: Optional["Hashes"] = Relationship(back_populates="evidence")
    metadata_record: Optional["MetadataRecord"] = Relationship(back_populates="evidence")
    forensics_results: List["ForensicsResult"] = Relationship(back_populates="evidence")
    deepfake_results: List["DeepfakeResult"] = Relationship(back_populates="evidence")
    ai_attribution_results: List["AIAttributionResult"] = Relationship(back_populates="evidence")
    malware_results: List["MalwareResult"] = Relationship(back_populates="evidence")
    osint_results: List["OSINTResult"] = Relationship(back_populates="evidence")
    provenance_records: List["ProvenanceRecord"] = Relationship(back_populates="evidence")
    blockchain_records: List["BlockchainRecord"] = Relationship(back_populates="evidence")
    audit_logs: List["AuditLog"] = Relationship(back_populates="evidence")
    reports: List["Report"] = Relationship(back_populates="evidence")

# 5. Uploads (supports chunking tracker)
class Upload(SQLModel, table=True):
    __tablename__ = "uploads"
    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: str = Field(foreign_key="evidence.id", unique=True)
    storage_path: str
    upload_status: str = Field(default="completed")  # chunking, assembling, completed, failed
    total_chunks: int = Field(default=1)
    uploaded_chunks: int = Field(default=1)
    integrity_valid: bool = Field(default=True)
    malware_scan_passed: bool = Field(default=True)
    duplicate_detected: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utc_now)

    evidence: Optional[Evidence] = Relationship(back_populates="upload")

# 6. Hashes (Cryptographic + Perceptual)
class Hashes(SQLModel, table=True):
    __tablename__ = "hashes"
    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: str = Field(foreign_key="evidence.id", unique=True)
    
    # Cryptographic Hashes
    md5: str = Field(index=True)
    sha256: str = Field(index=True)
    sha512: str = Field(index=True)
    
    # Perceptual/Acoustic Fingerprints (nullable for files that do not support them)
    p_hash: Optional[str] = Field(default=None, index=True)
    a_hash: Optional[str] = Field(default=None, index=True)
    d_hash: Optional[str] = Field(default=None, index=True)
    
    # Video/Audio keyframe and acoustic signatures stored as JSON
    video_signatures: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    audio_signatures: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    
    created_at: datetime = Field(default_factory=utc_now)

    evidence: Optional[Evidence] = Relationship(back_populates="hashes")

# 7. Metadata Record (exif, system, doc struct)
class MetadataRecord(SQLModel, table=True):
    __tablename__ = "metadata"
    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: str = Field(foreign_key="evidence.id", unique=True)
    
    # Common core fields
    creator: Optional[str] = None
    software_used: Optional[str] = None
    created_datetime: Optional[datetime] = None
    modified_datetime: Optional[datetime] = None
    gps_latitude: Optional[float] = None
    gps_longitude: Optional[float] = None
    
    # Raw unstructured metadata dump
    raw_metadata: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utc_now)

    evidence: Optional[Evidence] = Relationship(back_populates="metadata_record")

# 8. Image & Video Forensics Results
class ForensicsResult(SQLModel, table=True):
    __tablename__ = "forensics_results"
    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: str = Field(foreign_key="evidence.id")
    engine_name: str = Field(index=True)  # ELA, PRNU, Noise, CloneDetection, FFprobe
    tampered: bool = Field(default=False)
    confidence: float = Field(default=0.0)
    
    # Analysis outputs like coordinates of modifications or compressed maps
    output_details: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utc_now)

    evidence: Optional[Evidence] = Relationship(back_populates="forensics_results")

# 9. Deepfake Results
class DeepfakeResult(SQLModel, table=True):
    __tablename__ = "deepfake_results"
    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: str = Field(foreign_key="evidence.id")
    model_name: str = Field(index=True)  # Xception, EfficientNet, ViT, TimeSformer
    deepfake_probability: float = Field(default=0.0)
    confidence: float = Field(default=0.0)
    heatmap_path: Optional[str] = None
    explainability: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utc_now)

    evidence: Optional[Evidence] = Relationship(back_populates="deepfake_results")

# 10. AI Generated Content Attribution Results
class AIAttributionResult(SQLModel, table=True):
    __tablename__ = "ai_attribution_results"
    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: str = Field(foreign_key="evidence.id")
    predicted_source: str = Field(index=True)  # Midjourney, Stable Diffusion, Flux, Sora, DALL-E etc.
    probability: float = Field(default=0.0)
    confidence: float = Field(default=0.0)
    indicators: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utc_now)

    evidence: Optional[Evidence] = Relationship(back_populates="ai_attribution_results")

# 11. Malware Results
class MalwareResult(SQLModel, table=True):
    __tablename__ = "malware_results"
    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: str = Field(foreign_key="evidence.id")
    clamav_status: str  # clean, infected, failed
    yara_matches: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    virustotal_positives: int = Field(default=0)
    virustotal_total: int = Field(default=0)
    raw_vt_report: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    capa_indicators: Optional[Dict[str, Any]] = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=datetime.utcnow)

    evidence: Optional[Evidence] = Relationship(back_populates="malware_results")

# 12. OSINT Results
class OSINTResult(SQLModel, table=True):
    __tablename__ = "osint_results"
    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: str = Field(foreign_key="evidence.id")
    target_entity: str = Field(index=True)  # email, ip, domain, username
    discovery_timestamp: datetime = Field(default_factory=utc_now)
    raw_osint_data: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    relationships: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))  # Entity relation graph payload
    created_at: datetime = Field(default_factory=utc_now)

    evidence: Optional[Evidence] = Relationship(back_populates="osint_results")

# 13. Provenance Records (C2PA)
class ProvenanceRecord(SQLModel, table=True):
    __tablename__ = "provenance_records"
    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: str = Field(foreign_key="evidence.id")
    has_manifest: bool = Field(default=False)
    manifest_valid: bool = Field(default=False)
    creator: Optional[str] = None
    device: Optional[str] = None
    editing_history: List[Dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    verification_method: str = Field(default="C2PA Validator")
    created_at: datetime = Field(default_factory=utc_now)

    evidence: Optional[Evidence] = Relationship(back_populates="provenance_records")

# 14. Blockchain Records
class BlockchainRecord(SQLModel, table=True):
    __tablename__ = "blockchain_records"
    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: str = Field(foreign_key="evidence.id")
    chain_name: str = Field(index=True)  # Polygon, Hyperledger Fabric
    transaction_hash: str = Field(index=True)
    block_number: int
    registered_owner: str = Field(index=True)  # ETH address or certificate ID
    verification_status: str = Field(default="VERIFIED OWNER")  # VERIFIED OWNER, PROBABLE OWNER, UNKNOWN OWNER
    created_at: datetime = Field(default_factory=utc_now)

    evidence: Optional[Evidence] = Relationship(back_populates="blockchain_records")

# 15. Audit Logs (Chain of Custody)
class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_logs"
    id: Optional[int] = Field(default=None, primary_key=True)
    evidence_id: Optional[str] = Field(default=None, foreign_key="evidence.id", index=True)
    actor: str = Field(index=True)  # user email or system process
    operation: str = Field(index=True)  # Upload, Scan, Hash, Verification, Export
    hash_value: str = Field(index=True)  # SHA256 of the evidence at the time of operation
    result: str = Field(index=True)  # Success, Failure, Tampering Warning
    timestamp: datetime = Field(default_factory=utc_now)

    evidence: Optional[Evidence] = Relationship(back_populates="audit_logs")

# 16. User Session Traces
class UserSession(SQLModel, table=True):
    __tablename__ = "user_sessions"
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: str = Field(index=True, unique=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    user_email: str = Field(index=True)
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utc_now)
    last_seen_at: datetime = Field(default_factory=utc_now)

# 17. Document Forensic Traces
class DocumentTrace(SQLModel, table=True):
    __tablename__ = "document_traces"
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: str = Field(index=True)
    evidence_id: str = Field(foreign_key="evidence.id", unique=True, index=True)
    user_id: Optional[int] = Field(default=None, foreign_key="users.id", index=True)
    user_email: Optional[str] = Field(default=None, index=True)
    filename: str = Field(index=True)
    file_type: str = Field(index=True)
    mime_type: str
    file_size_bytes: int
    upload_timestamp: datetime = Field(default_factory=utc_now)
    extracted_content_summary: str = ""
    model_input_prompt: str = ""
    processing_steps: List[Dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    intermediate_reasoning: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    model_output: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    classifications: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    extracted_entities: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    warnings: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    errors: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    fallback_behavior: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    token_usage: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    processing_duration_ms: Optional[float] = None
    confidence_score: Optional[float] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

# 18. Reports
class Report(SQLModel, table=True):
    __tablename__ = "reports"
    id: Optional[str] = Field(default=None, primary_key=True)  # Unique Report Hash/UUID
    evidence_id: str = Field(foreign_key="evidence.id")
    generated_by: str
    storage_path: str
    digital_signature: str
    trust_score_snapshot: float
    risk_level_snapshot: str
    created_at: datetime = Field(default_factory=utc_now)

    evidence: Optional[Evidence] = Relationship(back_populates="reports")


# Schema wrappers for incoming/outgoing REST payloads
class UserCreate(BaseModel):
    email: str
    password: str
    full_name: str
    organization_name: str

class UserLogin(BaseModel):
    email: str
    password: str

class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    session_id: Optional[str] = None
