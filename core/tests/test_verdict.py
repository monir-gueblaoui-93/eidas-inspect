import io
import subprocess

from asn1crypto import x509 as asn1_x509
from cryptography.hazmat.primitives import serialization
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation.pdf_embedded import collect_embedded_signatures
from pyhanko.sign.validation.qualified.tsp import TSPRegistry

from eidas_inspect_core import (
    KsiVerificationTier,
    RevocationFetchers,
    SignatureType,
    VerdictReason,
    VerificationVerdict,
    verify_pdf,
)
from eidas_inspect_core.ksi_tool import KsiToolRunner
from pdf_fixtures import (
    QC_TYPE_ESIGN_OID,
    add_lta_timestamp,
    build_crl,
    build_ksi_sealed_pdf,
    build_minimal_pdf,
    generate_ca,
    generate_ca_issued_signer,
    generate_self_signed_signer,
    sign_pdf_bytes,
    tamper_page_after_signing,
)
from trust_list_fixtures import degraded_snapshot, fresh_snapshot, registry_with_granted_ca


def _asn1(cert_cx):
    return asn1_x509.Certificate.load(cert_cx.public_bytes(serialization.Encoding.DER))


def _qualified_signed_pdf_with_ca():
    """A QES-style signature (QcCompliance/QcSSCD/esign), issued by a
    separate CA (so revocation checking has somewhere to look), with a
    fresh (non-degraded) Trusted List snapshot granting that CA."""
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    signer, leaf_cert_cx = generate_ca_issued_signer(
        ca_key,
        ca_subject,
        ca_cert_cx,
        qc_compliance=True,
        qc_sscd=True,
        qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    signed = sign_pdf_bytes(build_minimal_pdf(), signer)
    snapshot = fresh_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))
    return signed, ca_key, ca_subject, snapshot


def test_confirmed_qualified_and_good_is_trusted():
    signed, ca_key, ca_subject, snapshot = _qualified_signed_pdf_with_ca()
    crl_der = build_crl(ca_key, ca_subject)

    async def crl_fetch(url):
        return crl_der

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(crl_fetch=crl_fetch),
    )

    assert result.verdict == VerificationVerdict.TRUSTED
    assert result.plain_summary == "Fully trusted — the signature is qualified and intact."
    assert result.verdict_breakdown.total == 1
    assert result.verdict_breakdown.confirmed_qualified == 1
    assert result.verdict_breakdown.issues == 0


def test_two_signatures_one_with_an_issue_is_partial_with_correct_counts():
    # Genuine tampering *between* two valid co-signatures: Alice signs,
    # the page is then actually altered, and Bob signs afterward. Alice's
    # own diff analysis (everything after her revision) correctly catches
    # the real edit; Bob's (nothing after his own, final revision) is
    # clean. Plain co-signing alone -- signing twice with no tampering in
    # between -- no longer produces an "issue" at all: see
    # test_two_valid_co_signers_is_trusted below, and _modification_status's
    # own FORM_FILLING handling for why.
    alice = generate_self_signed_signer('Alice', 'Org A')
    bob = generate_self_signed_signer('Bob', 'Org B')
    pdf = build_minimal_pdf()
    once = sign_pdf_bytes(pdf, alice, field_name='Signature1')
    tampered = tamper_page_after_signing(once)
    twice = sign_pdf_bytes(tampered, bob, field_name='Signature2')

    result = verify_pdf(twice)

    assert result.verdict == VerificationVerdict.PARTIAL
    assert result.plain_summary == "Partially trusted — 1 of 2 signatures has issues."
    assert result.verdict_breakdown.total == 2
    assert result.verdict_breakdown.issues == 1
    assert result.verdict_breakdown.confirmed_qualified == 0


def test_advanced_only_signature_is_partial_with_not_qualified_wording(signed_pdf):
    # A plain advanced signature (no qcStatements at all), nothing broken,
    # nothing unconfirmed -- simply not qualified. Distinct wording from
    # both "issues" and "unconfirmed": this is a known fact, not a problem
    # or a gap. Real-world regression case: Demo document.pdf hits exactly
    # this path.
    result = verify_pdf(signed_pdf)

    assert result.verdict == VerificationVerdict.PARTIAL
    assert result.plain_summary == "Partially trusted — the signature is valid but not qualified."
    assert result.verdict_breakdown.not_qualified == 1
    assert result.verdict_breakdown.issues == 0
    assert result.verdict_breakdown.unconfirmed == 0


def test_valid_but_trust_list_unavailable_is_partial_with_unconfirmed_wording(
    qes_signed_pdf,
):
    degraded = degraded_snapshot(TSPRegistry())  # issuer not found + degraded lists

    result = verify_pdf(qes_signed_pdf, trust_list=degraded)

    assert result.verdict == VerificationVerdict.PARTIAL
    assert "couldn't be confirmed" in result.plain_summary
    assert 'issues' not in result.plain_summary
    # Leads with "Valid signature" (reassurance), not a bare "could not be
    # confirmed" -- this is an honest TL-availability gap, not a defect in
    # the signature itself, and the wording shouldn't read as if it were.
    assert result.plain_summary == (
        "Valid signature — the EU Trusted List check is temporarily "
        "unavailable, so qualified status couldn't be confirmed right now."
    )
    assert result.verdict_breakdown.unconfirmed == 1
    assert result.verdict_breakdown.issues == 0


def test_multiple_valid_signatures_all_unconfirmed_is_partial_with_plural_wording():
    # The real-world shape reported live: several genuinely valid,
    # genuinely qualified co-signers, all UNCONFIRMED purely because the
    # EU Trusted List snapshot is degraded (e.g. one member state's list
    # failed to fetch this cycle) -- not a regression, not a problem with
    # any of the signatures. Locks in the plural "N of M" wording.
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    alice, _ = generate_ca_issued_signer(
        ca_key, ca_subject, ca_cert_cx, common_name='Alice',
        qc_compliance=True, qc_sscd=True, qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    bob, _ = generate_ca_issued_signer(
        ca_key, ca_subject, ca_cert_cx, common_name='Bob',
        qc_compliance=True, qc_sscd=True, qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    once = sign_pdf_bytes(build_minimal_pdf(), alice, field_name='Signature1')
    twice = sign_pdf_bytes(once, bob, field_name='Signature2')
    degraded = degraded_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))

    result = verify_pdf(twice, trust_list=degraded)

    assert result.verdict == VerificationVerdict.PARTIAL
    assert result.plain_summary == (
        "Valid signatures — the EU Trusted List check is temporarily "
        "unavailable, so qualified status couldn't be confirmed right now "
        "for 2 of 2."
    )
    assert result.verdict_breakdown.unconfirmed == 2
    assert result.verdict_breakdown.issues == 0


def test_all_tampered_is_not_trusted(tampered_signed_pdf):
    result = verify_pdf(tampered_signed_pdf)

    assert result.verdict == VerificationVerdict.NOT_TRUSTED
    assert result.plain_summary == "Do not rely on this document."
    assert result.verdict_breakdown.issues == result.verdict_breakdown.total


def test_revoked_only_item_is_not_trusted():
    signed, ca_key, ca_subject, snapshot = _qualified_signed_pdf_with_ca()
    revoked_crl = build_crl(ca_key, ca_subject, revoked_serial=_leaf_serial(signed))

    async def crl_fetch(url):
        return revoked_crl

    result = verify_pdf(
        signed,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(crl_fetch=crl_fetch),
    )

    assert result.verdict == VerificationVerdict.NOT_TRUSTED
    assert result.plain_summary == "Do not rely on this document."


def _leaf_serial(signed_pdf_bytes: bytes) -> int:
    reader = PdfFileReader(io.BytesIO(signed_pdf_bytes), strict=False)
    embedded = collect_embedded_signatures(reader)[0]
    return embedded.signer_cert.serial_number


def test_unsigned_pdf_is_no_signatures(unsigned_pdf):
    result = verify_pdf(unsigned_pdf)

    assert result.verdict == VerificationVerdict.NO_SIGNATURES
    assert result.plain_summary == 'This document contains no digital signatures.'
    assert result.verdict_breakdown is None


def test_appended_unconfirmed_lta_timestamp_does_not_demote_a_trusted_signature():
    signed, ca_key, ca_subject, snapshot = _qualified_signed_pdf_with_ca()
    crl_der = build_crl(ca_key, ca_subject)

    async def crl_fetch(url):
        return crl_der

    # add_lta_timestamp appends a standalone /DocTimeStamp from its own,
    # unregistered TSA -- it should show up as its own item, but must not
    # pull an otherwise fully-confirmed document down to PARTIAL.
    extended = add_lta_timestamp(signed)

    result = verify_pdf(
        extended,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(crl_fetch=crl_fetch),
    )

    assert len(result.items) == 2
    assert result.verdict == VerificationVerdict.TRUSTED
    assert result.verdict_breakdown.total == 1


# --- Bug fix: multiple independently-trustworthy items must be TRUSTED,
# not merely "more than one item" -- see PROGRESS.md's decision table. ---

_KSI_OK_DUMP = """
KSI Signature dump:
  Signing time: (1700000000) 2023-11-14 22:13:20 UTC+00:00
KSI Verification result dump:
  Final result:
    OK: No verification errors.
"""

_KSI_NA_DUMP = """
KSI Signature dump:
  Signing time: (1700000000) 2023-11-14 22:13:20 UTC+00:00
KSI Verification result dump:
  Final result:
    NA:\t[GEN-02] Verification inconclusive.
"""

_KSI_FAIL_DUMP = """
KSI Signature dump:
  Signing time: (1700000000) 2023-11-14 22:13:20 UTC+00:00
KSI Verification result dump:
  Final result:
    FAIL:\t[GEN-01] Wrong document.
"""


def _ksi_runner_stub(*, publication_dump=_KSI_NA_DUMP, key_dump=None, internal_dump=_KSI_OK_DUMP):
    """Minimal stand-in KsiToolRunner for verdict-level tests -- keyed off
    the same real CLI flags verify.py's own calls use (see test_ksi.py's
    fuller version, which this mirrors in miniature)."""

    def invoke(args, timeout_seconds):
        if '--ver-pub' in args:
            dump = publication_dump
        elif '--ver-key' in args:
            dump = key_dump
        else:
            dump = internal_dump
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=dump or '', stderr='')

    return KsiToolRunner(invoke=invoke)


def test_two_valid_co_signers_is_trusted():
    # This was the concrete, confirmed bug: any real multi-signer PDF used
    # to have its earlier signer(s) misreported as tampered purely because
    # someone else validly co-signed afterward (see _modification_status's
    # FORM_FILLING handling). With that fixed, two independently qualified,
    # TL-confirmed, non-revoked signers both read clean.
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    alice, _ = generate_ca_issued_signer(
        ca_key, ca_subject, ca_cert_cx, common_name='Alice',
        qc_compliance=True, qc_sscd=True, qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    bob, _ = generate_ca_issued_signer(
        ca_key, ca_subject, ca_cert_cx, common_name='Bob',
        qc_compliance=True, qc_sscd=True, qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    once = sign_pdf_bytes(build_minimal_pdf(), alice, field_name='Signature1')
    twice = sign_pdf_bytes(once, bob, field_name='Signature2')
    snapshot = fresh_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))
    crl_der = build_crl(ca_key, ca_subject)

    async def crl_fetch(url):
        return crl_der

    result = verify_pdf(
        twice,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(crl_fetch=crl_fetch),
    )

    assert result.verdict == VerificationVerdict.TRUSTED
    assert result.plain_summary == "Fully trusted — all 2 signatures are qualified and intact."
    assert result.verdict_breakdown.total == 2
    assert result.verdict_breakdown.confirmed_qualified == 2
    assert result.verdict_breakdown.issues == 0
    assert all(i.integrity.modified_after_signing is False for i in result.items)


def test_qes_and_publication_verified_ksi_seal_is_trusted():
    # Case 1 from the bug report: a real QES plus a genuinely
    # publication-verified KSI seal must be TRUSTED, not PARTIAL -- and the
    # wording must distinguish "qualified" (the signature) from
    # "independently verified" (the seal); never claim the seal is
    # qualified.
    #
    # KSI seal added *before* the signature, so the signature's own diff
    # analysis (which only looks at what happens after its own revision)
    # sees a clean trailing signature -- matches how this was verified
    # empirically before writing this test (see PROGRESS.md).
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    signer, _ = generate_ca_issued_signer(
        ca_key, ca_subject, ca_cert_cx,
        qc_compliance=True, qc_sscd=True, qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    pdf = sign_pdf_bytes(
        build_ksi_sealed_pdf(build_minimal_pdf(), field_name='KsiSeal1'), signer
    )
    snapshot = fresh_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))
    crl_der = build_crl(ca_key, ca_subject)

    async def crl_fetch(url):
        return crl_der

    runner = _ksi_runner_stub(publication_dump=_KSI_OK_DUMP)
    result = verify_pdf(
        pdf,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(crl_fetch=crl_fetch),
        ksi_runner=runner,
    )

    assert result.verdict == VerificationVerdict.TRUSTED
    assert result.plain_summary == (
        "Fully trusted — 1 of 2 items is qualified and intact; 1 is independently "
        "verified against a publicly witnessed record."
    )
    assert 'qualified' not in result.plain_summary.split(';')[1]
    assert result.verdict_breakdown.confirmed_qualified == 1
    assert result.verdict_breakdown.confirmed_independent == 1


def test_ksi_only_publication_verified_is_trusted_without_qualified_wording():
    # A KSI-only document (no X.509 item at all) can reach TRUSTED on its
    # own -- a publication-verified seal is a conclusive positive result
    # and isn't held to "must also have a QES". The wording must never
    # imply eIDAS qualification: "Trusted", not "Fully trusted"; no use of
    # the word "qualified" anywhere.
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())
    runner = _ksi_runner_stub(publication_dump=_KSI_OK_DUMP)

    result = verify_pdf(pdf, ksi_runner=runner)

    assert result.verdict == VerificationVerdict.TRUSTED
    assert result.plain_summary == (
        "Trusted — integrity independently verified against a publicly witnessed record."
    )
    assert 'qualified' not in result.plain_summary.lower()
    assert not result.plain_summary.startswith('Fully')
    assert result.verdict_breakdown.confirmed_independent == 1
    assert result.verdict_breakdown.confirmed_qualified == 0


def test_qes_and_calendar_verified_ksi_seal_is_trusted():
    # CALENDAR_VERIFIED (a real cryptographic check against the sealing
    # infrastructure's own certificate, just not a publicly witnessed
    # record) also counts as independently confirmed -- an intact,
    # calendar-verified seal must not drag an otherwise fully-trusted
    # document down to PARTIAL. Locks in the weaker-tier wording too.
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    signer, _ = generate_ca_issued_signer(
        ca_key, ca_subject, ca_cert_cx,
        qc_compliance=True, qc_sscd=True, qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    pdf = sign_pdf_bytes(
        build_ksi_sealed_pdf(build_minimal_pdf(), field_name='KsiSeal1'), signer
    )
    snapshot = fresh_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))
    crl_der = build_crl(ca_key, ca_subject)

    async def crl_fetch(url):
        return crl_der

    # Publication-based comes back NA (not yet extended), but the
    # key-based check holds -- CALENDAR_VERIFIED, not PUBLICATION_VERIFIED.
    runner = _ksi_runner_stub(publication_dump=_KSI_NA_DUMP, key_dump=_KSI_OK_DUMP)
    result = verify_pdf(
        pdf,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(crl_fetch=crl_fetch),
        ksi_runner=runner,
    )

    assert result.verdict == VerificationVerdict.TRUSTED
    assert result.plain_summary == (
        "Fully trusted — 1 of 2 items is qualified and intact; 1 is independently "
        "verified against the sealing infrastructure's own signing certificate."
    )
    assert result.verdict_breakdown.confirmed_independent == 1


def test_qes_and_internal_only_ksi_seal_is_trusted():
    # Correctness fix, not the original decision-table call: an intact
    # INTERNAL_ONLY KSI seal counts as CONFIRMED_INTACT, not UNCONFIRMED --
    # KSI answers an integrity question (has the document been altered
    # since sealing?), not a qualified-identity one, so "neither external
    # check was reachable yet" is not the same honest gap as an unconfirmed
    # qualified claim. A QES plus an intact KSI seal must be TRUSTED, with
    # wording that names each on its own terms -- never implying the KSI
    # seal is a failed/partial qualified signature.
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    signer, _ = generate_ca_issued_signer(
        ca_key, ca_subject, ca_cert_cx,
        qc_compliance=True, qc_sscd=True, qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    pdf = sign_pdf_bytes(
        build_ksi_sealed_pdf(build_minimal_pdf(), field_name='KsiSeal1'), signer
    )
    snapshot = fresh_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))
    crl_der = build_crl(ca_key, ca_subject)

    async def crl_fetch(url):
        return crl_der

    # Both independent checks come back NA -- INTERNAL_ONLY, the tier this
    # project's one real-world KSI sample currently lands on (see
    # PROGRESS.md's GlobalSign trust-chain-gap writeup).
    runner = _ksi_runner_stub(publication_dump=_KSI_NA_DUMP, key_dump=_KSI_NA_DUMP)
    result = verify_pdf(
        pdf,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(crl_fetch=crl_fetch),
        ksi_runner=runner,
    )

    ksi_item = next(i for i in result.items if i.type == SignatureType.KSI_SEAL)
    assert ksi_item.ksi_verification_tier == KsiVerificationTier.INTERNAL_ONLY
    assert ksi_item.verdict_reason == VerdictReason.CONFIRMED_INTACT
    assert result.verdict == VerificationVerdict.TRUSTED
    assert result.plain_summary == (
        "Fully trusted — 1 of 2 items is qualified and intact; 1 is an intact "
        "KSI seal with no independent external confirmation reachable."
    )
    assert 'qualified' not in result.plain_summary.split(';')[1]
    assert 'independently verified' not in result.plain_summary
    assert result.verdict_breakdown.confirmed_intact == 1
    assert result.verdict_breakdown.unconfirmed == 0


def test_ksi_only_internal_only_is_trusted_without_qualified_or_independent_wording():
    # A KSI-only document whose seal is intact but reached no external
    # corroboration must still be TRUSTED on its own -- the banner must
    # read as trusted/positive, not "Partially trusted", and must never
    # borrow "qualified" or "independently verified" language, since
    # neither claim applies to an internal-only result.
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())

    runner = _ksi_runner_stub(publication_dump=_KSI_NA_DUMP, key_dump=_KSI_NA_DUMP)
    result = verify_pdf(pdf, ksi_runner=runner)

    ksi_item = result.items[0]
    assert ksi_item.ksi_verification_tier == KsiVerificationTier.INTERNAL_ONLY
    assert ksi_item.verdict_reason == VerdictReason.CONFIRMED_INTACT
    assert result.verdict == VerificationVerdict.TRUSTED
    assert result.plain_summary == (
        "Trusted — this document's KSI seal is intact, and hasn't been "
        "altered since it was sealed. Independent confirmation against a "
        "public record wasn't reachable right now."
    )
    assert 'qualified' not in result.plain_summary.lower()
    assert 'independently verified' not in result.plain_summary
    assert not result.plain_summary.startswith('Fully')
    assert result.verdict_breakdown.confirmed_intact == 1
    assert result.verdict_breakdown.unconfirmed == 0


def test_broken_ksi_seal_alone_is_not_trusted():
    # A genuinely broken/inconsistent KSI seal -- the one case that must
    # still demote it off the trusted axis, per the corrected rule: only a
    # real integrity failure downgrades a KSI seal, never "couldn't reach a
    # stronger external confirmation".
    pdf = build_ksi_sealed_pdf(build_minimal_pdf(), malformed=True)

    result = verify_pdf(pdf)

    ksi_item = result.items[0]
    assert ksi_item.ksi_verification_tier == KsiVerificationTier.BROKEN
    assert ksi_item.verdict_reason == VerdictReason.BROKEN
    assert result.verdict == VerificationVerdict.NOT_TRUSTED
    assert result.plain_summary == "Do not rely on this document."


def test_ksi_only_not_verified_is_partial_without_qualified_wording():
    # A KSI seal that hasn't even had its internal check attempted yet
    # (no ksi_runner wired up) stays an honest UNCONFIRMED gap -- but the
    # wording must never say "qualified status", a claim reserved for
    # X.509 signatures/seals that actually make it. KSI makes no qualified
    # claim at all, in any tier.
    pdf = build_ksi_sealed_pdf(build_minimal_pdf())

    result = verify_pdf(pdf)

    ksi_item = result.items[0]
    assert ksi_item.ksi_verification_tier == KsiVerificationTier.NOT_VERIFIED
    assert ksi_item.verdict_reason == VerdictReason.UNCONFIRMED
    assert result.verdict == VerificationVerdict.PARTIAL
    assert 'qualified' not in result.plain_summary.lower()
    assert result.plain_summary == (
        "Partially trusted — verification could not be completed right now "
        "for 1 of 1 seal."
    )


def test_three_items_two_valid_one_broken_is_partial_with_correct_count():
    # Case 3 from the bug report: two genuinely valid, independently
    # trustworthy items plus one genuinely broken one must stay PARTIAL
    # with an accurate count -- the fix must never turn "mostly fine" into
    # either a false TRUSTED or a miscounted PARTIAL.
    ca_key, ca_subject, ca_cert_cx = generate_ca()
    alice, _ = generate_ca_issued_signer(
        ca_key, ca_subject, ca_cert_cx, common_name='Alice',
        qc_compliance=True, qc_sscd=True, qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    bob, _ = generate_ca_issued_signer(
        ca_key, ca_subject, ca_cert_cx, common_name='Bob',
        qc_compliance=True, qc_sscd=True, qc_type_oid=QC_TYPE_ESIGN_OID,
    )
    sealed = build_ksi_sealed_pdf(build_minimal_pdf(), field_name='KsiSeal1', malformed=True)
    once = sign_pdf_bytes(sealed, alice, field_name='Signature1')
    twice = sign_pdf_bytes(once, bob, field_name='Signature2')
    snapshot = fresh_snapshot(registry_with_granted_ca(_asn1(ca_cert_cx)))
    crl_der = build_crl(ca_key, ca_subject)

    async def crl_fetch(url):
        return crl_der

    result = verify_pdf(
        twice,
        trust_list=snapshot,
        check_revocation=True,
        revocation_fetchers=RevocationFetchers(crl_fetch=crl_fetch),
        ksi_runner=_ksi_runner_stub(),
    )

    assert result.verdict == VerificationVerdict.PARTIAL
    assert result.plain_summary == "Partially trusted — 1 of 3 items has issues."
    assert result.verdict_breakdown.total == 3
    assert result.verdict_breakdown.confirmed_qualified == 2
    assert result.verdict_breakdown.issues == 1
