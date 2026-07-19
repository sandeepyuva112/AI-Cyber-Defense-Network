from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.base import Base

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def initialize_database() -> None:
    if settings.database_url.startswith("sqlite:///"):
        db_path = Path(settings.database_url.removeprefix("sqlite:///"))
        db_path.parent.mkdir(parents=True, exist_ok=True)

    Base.metadata.create_all(bind=engine)

    # Seed default admin user if none exists
    db = SessionLocal()
    try:
        from app.db.models.user import User
        from app.api._common.auth import hash_password
        from datetime import datetime
        import uuid

        if db.query(User).count() == 0:
            admin_user = User(
                id=str(uuid.uuid4()),
                email="admin@cyberdefense.local",
                name="System Administrator",
                hashed_password=hash_password("admin"),
                role="admin",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(admin_user)
            db.commit()
    except Exception as e:
        db.rollback()
        # Non-fatal error during seeding; log it.
        import logging
        logging.getLogger("uvicorn").error(f"Error seeding default admin: {e}")
    finally:
        db.close()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

