from sqlmodel import SQLModel, create_engine, Session
from sqlalchemy.pool import StaticPool
from app.config import settings

engine_kwargs = {
    "echo": False,
    "pool_pre_ping": True,
}

if settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs.update(
        {
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
        }
    )

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)

def init_db():
    # This imports all models so SQLModel metadata registers them
    from app.models import schemas  # noqa: F401
    SQLModel.metadata.create_all(engine)

def get_db():
    with Session(engine) as session:
        yield session
