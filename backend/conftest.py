import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

BACKEND_ROOT = Path(__file__).resolve().parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

test_db_file = BACKEND_ROOT / "test_runtime.db"
if test_db_file.exists():
    try:
        test_db_file.unlink()
    except Exception:
        pass

os.environ.setdefault("DATABASE_URL", f"sqlite:///{test_db_file}")


from app.db import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.schemas import Case, Organization, User  # noqa: E402
from app.services.hashing_service import HashingService  # noqa: E402

TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@pytest.fixture(name="session")
def session_fixture():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        org = Organization(name="Test Security Unit")
        session.add(org)
        session.commit()
        session.refresh(org)

        user = User(
            email="tester@deeptrace.ai",
            hashed_password=HashingService.hash_password("testpassword"),
            full_name="Jane Doe",
            role="analyst",
            organization_id=org.id,
        )
        session.add(user)
        session.commit()
        session.refresh(user)

        case = Case(
            case_number="CASE-2026-TEST",
            title="Test Case",
            description="Testing suite workspace",
            creator_id=user.id,
        )
        session.add(case)
        session.commit()

        yield session
    SQLModel.metadata.drop_all(engine)


@pytest.fixture(name="client")
def client_fixture(session):
    def get_db_override():
        return session

    app.dependency_overrides[get_db] = get_db_override
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()

