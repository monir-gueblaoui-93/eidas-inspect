"""KSI (Guardtime Keyless Signature Infrastructure) seal detection and
verification-tier computation via verify_pdf().

Checkpoint 1: find /FT /KSI AcroForm fields at all -- pyHanko's own
collect_embedded_signatures() filters strictly on /FT /Sig and silently
never sees them, which was a live bug (a KSI-sealed document used to
report NO_SIGNATURES).

Checkpoint 2: given a KsiToolRunner, actually run the internal-consistency
and publication-based checks (real subprocess calls to Guardtime's own
ksi-tool -- see .ksi_tool) and map the result onto KsiVerificationTier.
Every test below injects a stubbed runner (never shells out to a real
binary); test_ksi_tool_integration.py separately exercises the real
binary end-to-end (skipped automatically if it isn't installed).
"""

import subprocess

from eidas_inspect_core import (
    KsiVerificationTier,
    SignatureType,
    VerdictReason,
    VerificationVerdict,
    verify_pdf,
)
from eidas_inspect_core.ksi_tool import KsiToolRunner
from pdf_fixtures import build_ksi_sealed_pdf, build_minimal_pdf, sign_pdf_bytes

_REAL_OK_DUMP = """
KSI Signature dump:
  Signing time: (1700000000) 2023-11-14 22:13:20 UTC+00:00
  Identity Metadata:
    1) Client ID: 'GT', Machine ID: 'anon:1', Sequence number: 1, Request time: (1700000000.0) 2023-11-14 22:13:20 UTC+00:00

KSI Verification result dump:
  Final result:
    OK: No verification errors.
"""

_REAL_FAIL_DUMP = """
KSI Signature dump:
  Signing time: (1700000000) 2023-11-14 22:13:20 UTC+00:00

KSI Verification result dump:
  Final result:
    FAIL:\t[GEN-01] Wrong document.\tIn rule:\tDocumentHashVerification
"""

_REAL_NA_DUMP = """
KSI Signature dump:
  Signing time: (1700000000) 2023-11-14 22:13:20 UTC+00:00

KSI Verification result dump:
  Final result:
    NA:\t[GEN-02] Verification inconclusive.\tIn rule:\tPublicationsFileContainsSuitablePublication
"""


def _stub_ksi_runner(
    *,
    internal_dump: str,
    publication_dump: str | None = None,
    key_dump: str | None = None,
) -> KsiToolRunner:
    """A KsiToolRunner whose subprocess boundary is entirely faked --
    returns internal_dump for --ver-int calls, publication_dump for
    --ver-pub calls, and key_dump for --ver-key calls, keyed off the real
    CLI flags verify.py's own calls use, so this stays a faithful stand-in
    regardless of exact temp file paths (which verify_pdf generates itself
    and this test can't predict).
    """

    def invoke(args, timeout_seconds):
        if '--ver-pub' in args:
            dump = publication_dump
        elif '--ver-key' in args:
            dump = key_dump
        else:
            dump = internal_dump
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=dump or '', stderr='')

    return KsiToolRunner(invoke=invoke)


def test_ksi_sealed_pdf_no_longer_reports_no_signatures():
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())

    result = verify_pdf(pdf)

    assert result.verdict != VerificationVerdict.NO_SIGNATURES
    assert len(result.items) == 1


def test_ksi_seal_item_has_expected_fields():
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())

    result = verify_pdf(pdf)

    item = result.items[0]
    assert item.type == SignatureType.KSI_SEAL
    assert item.ksi_verification_tier == KsiVerificationTier.NOT_VERIFIED
    assert item.verdict_reason == VerdictReason.UNCONFIRMED
    assert 'KSI' in item.plain_explanation
    assert 'not' in item.plain_explanation.lower()  # honestly says "not yet verified"
    assert item.technical_detail is not None
    # These are explicitly not meaningful signals for KSI items yet (see
    # _build_ksi_seal_item's docstring) -- just confirming they're set to
    # the documented "not a detected problem" placeholder, not asserting
    # they mean anything cryptographically.
    assert item.integrity.intact is True
    assert item.integrity.signature_valid is True


def test_malformed_ksi_seal_is_reported_as_broken():
    pdf = build_ksi_sealed_pdf(build_minimal_pdf(), malformed=True)

    result = verify_pdf(pdf)

    item = result.items[0]
    assert item.type == SignatureType.KSI_SEAL
    assert item.ksi_verification_tier == KsiVerificationTier.BROKEN
    assert item.verdict_reason == VerdictReason.BROKEN
    assert item.integrity.intact is False
    assert item.integrity.signature_valid is False


def test_ksi_seal_alongside_an_ordinary_signature(signer):
    base = sign_pdf_bytes(build_minimal_pdf(), signer)
    pdf = build_ksi_sealed_pdf(base, field_name='KsiSeal1')

    result = verify_pdf(pdf)

    assert len(result.items) == 2
    types = {item.type for item in result.items}
    assert types == {SignatureType.SIGNATURE, SignatureType.KSI_SEAL}


def test_unsigned_pdf_without_any_ksi_field_still_reports_no_signatures():
    # Regression guard: plain PDFs with no AcroForm at all must still hit
    # the NO_SIGNATURES path -- the new KSI discovery path must be a
    # strict addition, not a change to the "nothing found" case.
    result = verify_pdf(build_minimal_pdf())

    assert result.verdict == VerificationVerdict.NO_SIGNATURES
    assert result.items == []


# --- Checkpoint 2: verification-tier computation via a stubbed ksi-tool ---


def test_publication_verified_when_both_checks_pass():
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())
    runner = _stub_ksi_runner(internal_dump=_REAL_OK_DUMP, publication_dump=_REAL_OK_DUMP)

    result = verify_pdf(pdf, ksi_runner=runner)

    item = result.items[0]
    assert item.ksi_verification_tier == KsiVerificationTier.PUBLICATION_VERIFIED
    assert item.verdict_reason == VerdictReason.CONFIRMED_INDEPENDENT
    assert 'independently verifiable' in item.plain_explanation.lower()
    assert item.ksi_aggregation_time is not None
    assert item.ksi_identity_chain == ('GT:anon:1',)


def test_internal_only_when_all_three_checks_are_inconclusive():
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())
    runner = _stub_ksi_runner(
        internal_dump=_REAL_OK_DUMP, publication_dump=_REAL_NA_DUMP, key_dump=_REAL_NA_DUMP
    )

    result = verify_pdf(pdf, ksi_runner=runner)

    item = result.items[0]
    assert item.ksi_verification_tier == KsiVerificationTier.INTERNAL_ONLY
    assert item.verdict_reason == VerdictReason.UNCONFIRMED
    assert 'inconclusive' in item.technical_detail.lower()


def test_calendar_verified_when_key_based_check_passes():
    # Publication-based comes back NA (not yet extended -- the common case
    # for a freshly-sealed document), but the weaker key-based tier holds:
    # confirmed reachable against a real Scrive-produced KSI seal that
    # carries a Calendar Authentication Record (see PROGRESS.md).
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())
    runner = _stub_ksi_runner(
        internal_dump=_REAL_OK_DUMP, publication_dump=_REAL_NA_DUMP, key_dump=_REAL_OK_DUMP
    )

    result = verify_pdf(pdf, ksi_runner=runner)

    item = result.items[0]
    assert item.ksi_verification_tier == KsiVerificationTier.CALENDAR_VERIFIED
    assert item.verdict_reason == VerdictReason.CONFIRMED_INDEPENDENT
    assert 'signing certificate' in item.plain_explanation.lower()


def test_broken_when_key_based_check_actively_fails():
    # Distinct from NA/inconclusive: a key-based FAIL means a real
    # mismatch was found, not just "couldn't confirm" -- must not be
    # downgraded to a milder tier.
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())
    runner = _stub_ksi_runner(
        internal_dump=_REAL_OK_DUMP, publication_dump=_REAL_NA_DUMP, key_dump=_REAL_FAIL_DUMP
    )

    result = verify_pdf(pdf, ksi_runner=runner)

    item = result.items[0]
    assert item.ksi_verification_tier == KsiVerificationTier.BROKEN
    assert item.verdict_reason == VerdictReason.BROKEN


def test_broken_when_internal_check_fails():
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())
    runner = _stub_ksi_runner(internal_dump=_REAL_FAIL_DUMP)

    result = verify_pdf(pdf, ksi_runner=runner)

    item = result.items[0]
    assert item.ksi_verification_tier == KsiVerificationTier.BROKEN
    assert item.verdict_reason == VerdictReason.BROKEN
    assert item.integrity.intact is False
    assert item.integrity.signature_valid is False
    assert 'Wrong document' in item.technical_detail


def test_broken_when_internal_passes_but_publication_check_actively_fails():
    # Distinct from NA/inconclusive: a publication-based FAIL means a real
    # mismatch was found, not just "nothing to check yet" -- must not be
    # downgraded to a milder "couldn't confirm" tier.
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())
    runner = _stub_ksi_runner(internal_dump=_REAL_OK_DUMP, publication_dump=_REAL_FAIL_DUMP)

    result = verify_pdf(pdf, ksi_runner=runner)

    item = result.items[0]
    assert item.ksi_verification_tier == KsiVerificationTier.BROKEN
    assert item.verdict_reason == VerdictReason.BROKEN


def test_tool_error_on_internal_check_falls_back_to_not_verified():
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())
    runner = _stub_ksi_runner(internal_dump='not a real dump at all')

    result = verify_pdf(pdf, ksi_runner=runner)

    item = result.items[0]
    assert item.ksi_verification_tier == KsiVerificationTier.NOT_VERIFIED
    assert item.verdict_reason == VerdictReason.UNCONFIRMED
    # Not "broken" -- the tool simply couldn't answer, which is a
    # different, milder honesty gap than a confirmed problem.
    assert item.integrity.intact is True
