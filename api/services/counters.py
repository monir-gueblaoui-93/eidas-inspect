"""Anonymous verification counters: date, verdict, count. Nothing else --
no IP addresses, no filenames, no document content, ever persisted here.
"""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from ..config import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS daily_verdict_counts (
    date TEXT NOT NULL,
    verdict TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (date, verdict)
);
"""


@contextmanager
def _connect(db_path: str):
    os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def record_verdict(verdict: str, *, db_path: str = settings.counters_db_path) -> None:
    today = datetime.now(timezone.utc).date().isoformat()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO daily_verdict_counts (date, verdict, count)
            VALUES (?, ?, 1)
            ON CONFLICT (date, verdict) DO UPDATE SET count = count + 1
            """,
            (today, verdict),
        )
