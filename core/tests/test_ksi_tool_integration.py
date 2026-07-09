"""Real-binary integration test for KsiToolRunner.

Skipped automatically when `ksi-tool` isn't installed (it isn't part of
the default dev setup -- see DEPLOY.md/Dockerfile for how the production
image gets it). Exercises the real subprocess path against a genuine
Guardtime-issued KSI signature (see fixtures/ksi/README.md for
provenance), rather than the stubbed output every other KSI test uses --
this is the one place that would catch a real behavior change in
ksi-tool itself (a new version renaming its output tokens, say) that
stubbed tests, by construction, cannot.
"""

import shutil
from pathlib import Path

import pytest

from eidas_inspect_core.ksi_tool import KsiCheckOutcome, KsiToolRunner

FIXTURES = Path(__file__).parent / 'fixtures' / 'ksi'

pytestmark = pytest.mark.skipif(
    shutil.which('ksi') is None, reason='ksi-tool is not installed'
)


def test_real_ksi_tool_confirms_internal_consistency():
    runner = KsiToolRunner()

    result = runner.verify_internal(
        str(FIXTURES / 'demo-signature.ksig'), str(FIXTURES / 'demo-covered.bin')
    )

    assert result.outcome is KsiCheckOutcome.OK
    assert result.identity_chain is not None
    assert len(result.identity_chain) > 0
    assert result.aggregation_time is not None


def test_real_ksi_tool_detects_a_tampered_document():
    tampered = bytearray((FIXTURES / 'demo-covered.bin').read_bytes())
    tampered[-1] ^= 0xFF

    import tempfile

    with tempfile.NamedTemporaryFile(suffix='.bin') as tmp:
        tmp.write(bytes(tampered))
        tmp.flush()

        runner = KsiToolRunner()
        result = runner.verify_internal(str(FIXTURES / 'demo-signature.ksig'), tmp.name)

    assert result.outcome is KsiCheckOutcome.FAIL


def test_real_ksi_tool_reports_na_for_an_unextended_signature():
    # This fixture is genuinely unextended (signed 2019-04-05, no
    # publication record) -- NA is the correct, expected result, not a
    # test failure waiting to happen once the signature "ages out".
    # This specific check needs a live fetch of Guardtime's publications
    # file (ksi-tool does the fetch itself, given -P a URL) -- unlike
    # every other KSI test, it isn't fully offline; TOOL_ERROR is
    # tolerated here too so a flaky/offline network doesn't fail this
    # suite over something unrelated to ksi-tool's own correctness.
    runner = KsiToolRunner()

    result = runner.verify_publication_based(
        str(FIXTURES / 'demo-signature.ksig'), str(FIXTURES / 'demo-covered.bin')
    )

    assert result.outcome in (KsiCheckOutcome.NA, KsiCheckOutcome.TOOL_ERROR)
