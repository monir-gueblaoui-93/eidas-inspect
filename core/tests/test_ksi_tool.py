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

# Real output from: ksi verify --ver-key -i sample.ksig -f covered.bin
#   -P http://verify.guardtime.com/ksi-publications.bin
#   --cnstr "E=publications@guardtime.com" --dump
# Captured against a real Scrive-produced KSI seal (not the Guardtime demo
# file) -- this one *does* carry a Calendar Authentication Record, but the
# check still lands on NA: ksi-tool can't validate the record's PKI
# signature because the chain runs through GlobalSign's "Document Signing
# Root R45", which isn't in this environment's CA trust store (same gap
# already hit and documented for verify_publication_based -- see
# PROGRESS.md's KSI research notes).
_REAL_KEY_BASED_NA_CERT_TRUST_STDOUT = """
KSI Signature dump:
  Signing time: (1783519668) 2026-07-08 14:07:48 UTC+00:00
  Trust anchor: Calendar Authentication Record.

Calendar Authentication Record PKI signature:
  Signing certificate ID: 5c:e0:25:a7
  Signing certificate issued to: CN=H5 O=Guardtime

KSI Verification result dump:
  Verification abstract:
    Verifying calendar authentication record... na
  Verification details:
    NA:\t[GEN-02] Verification inconclusive.\tIn rule:\tCertificateExistence (Ksierr: 0x109 The PKI certificate is not trusted. Exterr: 'Unable to verify certificate: (error = 20) unable to get local issuer certificate')
  Final result:
    NA:\t[GEN-02] Verification inconclusive.\tIn rule:\tCertificateExistence (Ksierr: 0x109 The PKI certificate is not trusted. Exterr: 'Unable to verify certificate: (error = 20) unable to get local issuer certificate')
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


def test_key_based_verification_uses_the_ver_key_flag():
    calls = []

    def invoke(args, timeout_seconds):
        calls.append(args)
        return subprocess.CompletedProcess(
            args=args, returncode=0, stdout=_REAL_OK_STDOUT, stderr=''
        )

    runner = KsiToolRunner(invoke=invoke)
    result = runner.verify_key_based('sig.ksig', 'data.bin')

    assert result.outcome is KsiCheckOutcome.OK
    assert '--ver-key' in calls[0]
    assert '-P' in calls[0]
    assert '--cnstr' in calls[0]


def test_real_key_based_na_output_on_an_untrusted_pki_chain_is_parsed_correctly():
    # Confirms the empirically-observed environment gap (missing GlobalSign
    # "Document Signing Root R45" trust anchor) surfaces as an honest NA,
    # not a false OK or an unlabeled crash.
    runner = _stub_runner(_REAL_KEY_BASED_NA_CERT_TRUST_STDOUT, returncode=6)

    result = runner.verify_key_based('sig.ksig', 'data.bin')

    assert result.outcome is KsiCheckOutcome.NA
    assert result.detail is not None
    assert 'not trusted' in result.detail.lower()


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
