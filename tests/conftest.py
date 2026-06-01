"""Pytest configuration.

Sets up a temporary SQLite database for testing.
"""

import os
import sys
import tempfile

# Ensure api package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Create a temp file for the test database
_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_db_path = _db_file.name
_db_file.close()

# Set test environment variables BEFORE importing app
os.environ["JWT_SECRET"] = "test-secret-for-testing-at-least-32-chars!!"
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from api.models.database import Base, get_db
from api.main import app

# Override the app's DB dependency to provide clean sessions per request
@pytest.fixture(autouse=True)
def setup_db():
    """Recreate all tables before each test."""
    from api.models.database import engine, SessionLocal as _SL

    # Ensure check_same_thread=False for SQLite (needed for TestClient)
    if "check_same_thread" not in str(engine.url):
        # Recreate engine if needed
        import api.models.database as db_mod
        db_mod.engine = create_engine(
            f"sqlite:///{_db_path}",
            connect_args={"check_same_thread": False},
        )
        db_mod.SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=db_mod.engine
        )

    Base.metadata.create_all(bind=engine)
    yield
    # Clean up after test
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="session", autouse=True)
def cleanup():
    """Clean up temp database at end of session."""
    yield
    try:
        os.unlink(_db_path)
    except OSError:
        pass