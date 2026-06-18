from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlmodel import Session, select

from app.config import settings
from app.db import init_db, engine
from app.models.schemas import Organization, User, Case
from app.routers.endpoints import router as api_router
from app.services.hashing_service import HashingService

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize DB Tables
    init_db()
    
    # 2. Seed Default Database Data
    with Session(engine) as session:
        # Check and seed Organization
        org = session.exec(select(Organization).where(Organization.name == "DeepTrace Labs")).first()
        if not org:
            org = Organization(name="DeepTrace Labs")
            session.add(org)
            session.commit()
            session.refresh(org)

        # Check and seed default User
        user = session.exec(select(User).where(User.email == "analyst@deeptrace.ai")).first()
        if not user:
            user = User(
                email="analyst@deeptrace.ai",
                hashed_password=HashingService.hash_password("password"),
                full_name="Forensic Analyst Alex",
                role="analyst",
                organization_id=org.id
            )
            session.add(user)
            session.commit()
            session.refresh(user)

        # Check and seed default Cases
        cases = session.exec(select(Case)).all()
        if not cases:
            case_1 = Case(
                case_number="CASE-2026-0001",
                title="Deepfake Audio Campaign Detection",
                description="Investigation of suspicious political voice recording distributed on social channels.",
                creator_id=user.id
            )
            case_2 = Case(
                case_number="CASE-2026-0002",
                title="Corporate Espionage PDF Leak",
                description="Integrity checking of leaked intellectual property documents.",
                creator_id=user.id
            )
            case_3 = Case(
                case_number="CASE-2026-0003",
                title="Phishing Campaign Domain Audit",
                description="Investigating metadata alignment and threat intelligence signals for landing pages.",
                creator_id=user.id
            )
            session.add_all([case_1, case_2, case_3])
            session.commit()
            
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Unified Cyber Forensics, Provenance, Deepfake, and Trust Intelligence platform.",
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# Include core router
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/")
def read_root():
    return {
        "status": "healthy",
        "platform": settings.PROJECT_NAME,
        "api_docs": "/docs"
    }
