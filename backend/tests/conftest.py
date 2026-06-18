import os
import sys
import tempfile
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parent.parent
TEST_TEMP_ROOT = Path(
    os.environ.get(
        "TEST_TEMP_ROOT",
        tempfile.mkdtemp(prefix="deeptrace-tests-"),
    )
)

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# Use a file-backed sqlite database for test collection and lifespan startup.
# The test suite overrides request-time DB access, but the app startup lifecycle
# still needs a safe engine that does not require Postgres.
os.environ.setdefault("DATABASE_URL", f"sqlite:///{BACKEND_ROOT / 'test_runtime.db'}")
os.environ.setdefault("TMP", str(TEST_TEMP_ROOT))
os.environ.setdefault("TEMP", str(TEST_TEMP_ROOT))
os.environ.setdefault("TMPDIR", str(TEST_TEMP_ROOT))
tempfile.tempdir = str(TEST_TEMP_ROOT)
TEST_TEMP_ROOT.mkdir(parents=True, exist_ok=True)
