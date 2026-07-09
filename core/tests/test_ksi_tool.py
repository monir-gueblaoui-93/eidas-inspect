"""KsiToolRunner / _parse_dump tests.

Every canned stdout blob below is real ksi-tool 2.9.1374 output, captured
by running the actual binary (installed locally via Homebrew's official
guardtime/ksi tap) against a real Guardtime-issued KSI signature
(github.com/guardtime/ksi-pdf-verifier's demo/signed.pdf) -- not
hand-written guesses. See PROGRESS.md's KSI research notes. Tests stay
fully offline via the injectable ``invoke`` hook (same DI pattern as
``RevocationFetchers``); nothing here shells out to a real binary.
"""

import subprocess
from datetime import datetime, timezone

from eidas_inspect_core.ksi_tool import KsiCheckOutcome, KsiToolRunner

# Real output from: ksi verify --ver-int -i demo.ksig -f covered.bin --dump
_REAL_OK_STDOUT = """
KSI Signature dump:
  Input hash: SHA-256:dd5a1ecd3e0588b20c6612181825187a8bd71104203adcad9d28a203962244a5
  Signing time: (1554467559) 2019-04-05 12:32:39 UTC+00:00
  Identity Metadata:
    1) Client ID: 'GT', Machine ID: 'ANe2:0', Sequence number: 6, Request time: (1554467559.152942) 2019-04-05 12:32:39 UTC+00:00
    2) Client ID: 'GT', Machine ID: 'ASe2-0:1', Sequence number: 3, Request time: (1554467559.137795) 2019-04-05 12:32:39 UTC+00:00
    3) Client ID: 'GT', Machine ID: 'ALe2-1-2:6', Sequence number: 5, Request time: (1554467558.749950) 2019-04-05 12:32:38 UTC+00:00
    4) Client ID: 'anon', Machine ID: 'ksigw-testuser:1', Sequence number: 0, Request time: (1554467558.590415) 2019-04-05 12:32:38 UTC+00:00
  Trust anchor: Calendar Authentication Record.

KSI Verification result dump:
  Verification abstract:
    Verifying document hash... ok
    Verifying aggregation hash chain internal consistency... ok
  Verification details:
    OK: No verification errors.\tIn rule:\tDocumentHashVerification
  Final result:
    OK: No verification errors.
"""

# Real output from: ksi verify --ver-int -i demo.ksig -f tampered.bin --dump
# (tampered.bin: covered.bin with its last byte XORed)
_REAL_FAIL_STDOUT = """
KSI Signature dump:
  Input hash: SHA-256:dd5a1ecd3e0588b20c6612181825187a8bd71104203adcad9d28a203962244a5
  Signing time: (1554467559) 2019-04-05 12:32:39 UTC+00:00
  Identity Metadata:
    1) Client ID: 'GT', Machine ID: 'ANe2:0', Sequence number: 6, Request time: (1554467559.152942) 2019-04-05 12:32:39 UTC+00:00
    4) Client ID: 'anon', Machine ID: 'ksigw-testuser:1', Sequence number: 0, Request time: (1554467558.590415) 2019-04-05 12:32:38 UTC+00:00

KSI Verification result dump:
  Verification abstract:
    Verifying document hash... failed
  Verification details:
    OK: No verification errors.\tIn rule:\tDocumentHashExistence
    FAIL:\t[GEN-01] Wrong document.\tIn rule:\tDocumentHashVerification
  Final result:
    FAIL:\t[GEN-01] Wrong document.\tIn rule:\tDocumentHashVerification


Document hash: SHA-256:280ec878996a1b27e802aa28717d0de2cdfacd119aae3b5f5a20174343641ffc
"""

# Real output from: ksi verify --ver-pub -i demo.ksig -f covered.bin
#   -P http://verify.guardtime.com/ksi-publications.bin
#   --cnstr "E=publications@guardtime.com" --dump
# (this signature is genuinely unextended -- no publication record --
# which is the expected, common case this tier exists to describe)
_REAL_NA_STDOUT = """
KSI Signature dump:
  Input hash: SHA-256:dd5a1ecd3e0588b20c6612181825187a8bd71104203adcad9d28a203962244a5
  Signing time: (1554467559) 2019-04-05 12:32:39 UTC+00:00
  Identity Metadata:
    1) Client ID: 'GT', Machine ID: 'ANe2:0', Sequence number: 6, Request time: (1554467559.152942) 2019-04-05 12:32:39 UTC+00:00

KSI Verification result dump:
  Verification abstract:
    Verifying publication... na
  Verification details:
    OK: No verification errors.\tIn rule:\tSignaturePublicationRecordMissing
    NA:\t[GEN-02] Verification inconclusive.\tIn rule:\tPublicationsFileContainsSuitablePublication
  Final result:
    NA:\t[GEN-02] Verification inconclusive.\tIn rule:\tPublicationsFileContainsSuitablePublication
"""


def _stub_runner(stdout: str, returncode: int = 0) -> KsiToolRunner:
    def invoke(args, timeout_seconds):
        return subprocess.CompletedProcess(
            args=args, returncode=returncode, stdout=stdout, stderr=''
        )

    return KsiToolRunner(invoke=invoke)


def test_real_ok_output_is_parsed_correctly():
    runner = _stub_runner(_REAL_OK_STDOUT, returncode=0)

    result = runner.verify_internal('sig.ksig', 'data.bin')

    assert result.outcome is KsiCheckOutcome.OK
    assert result.detail is None
    assert result.aggregation_time == datetime(2019, 4, 5, 12, 32, 39, tzinfo=timezone.utc)
    assert result.identity_chain == (
        'GT:ANe2:0',
        'GT:ASe2-0:1',
        'GT:ALe2-1-2:6',
        'anon:ksigw-testuser:1',
    )


def test_real_fail_output_is_parsed_correctly():
    runner = _stub_runner(_REAL_FAIL_STDOUT, returncode=6)

    result = runner.verify_internal('sig.ksig', 'tampered.bin')

    assert result.outcome is KsiCheckOutcome.FAIL
    assert result.detail is not None
    assert 'Wrong document' in result.detail
    assert result.identity_chain == ('GT:ANe2:0', 'anon:ksigw-testuser:1')


def test_real_na_output_for_an_unextended_signature_is_parsed_correctly():
    runner = _stub_runner(_REAL_NA_STDOUT, returncode=6)

    result = runner.verify_publication_based('sig.ksig', 'data.bin')

    assert result.outcome is KsiCheckOutcome.NA
    assert result.detail is not None
    assert 'inconclusive' in result.detail.lower()


def test_bad_invocation_with_no_final_result_line_is_a_tool_error():
    runner = _stub_runner('Maybe you want to: ...\n', returncode=3)

    result = runner.verify_internal('sig.ksig', 'data.bin')

    assert result.outcome is KsiCheckOutcome.TOOL_ERROR
    assert result.detail is not None


def test_binary_not_found_is_a_tool_error_not_an_exception():
    def invoke(args, timeout_seconds):
        raise FileNotFoundError('no such file: ksi')

    runner = KsiToolRunner(invoke=invoke)

    result = runner.verify_internal('sig.ksig', 'data.bin')

    assert result.outcome is KsiCheckOutcome.TOOL_ERROR
    assert 'no such file' in result.detail


def test_timeout_is_a_tool_error_not_an_exception():
    def invoke(args, timeout_seconds):
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout_seconds)

    runner = KsiToolRunner(invoke=invoke)

    result = runner.verify_internal('sig.ksig', 'data.bin')

    assert result.outcome is KsiCheckOutcome.TOOL_ERROR
