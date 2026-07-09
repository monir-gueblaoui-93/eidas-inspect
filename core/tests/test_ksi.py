"""KSI (Guardtime Keyless Signature Infrastructure) seal detection.

Checkpoint 1 of the KSI feature: find /FT /KSI AcroForm fields at all --
pyHanko's own collect_embedded_signatures() filters strictly on /FT /Sig
and silently never sees them, which is a live bug (a KSI-sealed document
used to report NO_SIGNATURES). No cryptographic verification is performed
yet; see PROGRESS.md's KSI research notes and models.KsiVerificationTier
for the verification-tiers phase that comes next.
"""

from eidas_inspect_core import (
    KsiVerificationTier,
    SignatureType,
    VerdictReason,
    VerificationVerdict,
    verify_pdf,
)
from pdf_fixtures import build_ksi_sealed_pdf, build_minimal_pdf, sign_pdf_bytes


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
