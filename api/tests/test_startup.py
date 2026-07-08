import logging
import os
import stat

import pytest

from api.startup import FALLBACK_COUNTERS_DB_PATH, resolve_counters_db_path


def test_writable_path_is_returned_as_is(tmp_path):
    target = tmp_path / 'sub' / 'counters.db'

    resolved = resolve_counters_db_path(str(target))

    assert resolved == str(target)
    assert target.parent.is_dir()


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses permission checks")
def test_unwritable_path_falls_back_to_tmp_with_a_warning(tmp_path, caplog):
    readonly_dir = tmp_path / 'readonly'
    readonly_dir.mkdir()
    readonly_dir.chmod(stat.S_IREAD | stat.S_IEXEC)  # no write permission
    target = readonly_dir / 'sub' / 'counters.db'

    try:
        with caplog.at_level(logging.WARNING):
            resolved = resolve_counters_db_path(str(target))
    finally:
        readonly_dir.chmod(stat.S_IRWXU)  # restore so tmp_path cleanup can remove it

    assert resolved == FALLBACK_COUNTERS_DB_PATH
    assert "isn't writable" in caplog.text
