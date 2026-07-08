from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class VerificationVerdict(StrEnum):
    TRUSTED = 'trusted'
    PARTIAL = 'partial'
    NOT_TRUSTED = 'not-trusted'
    NO_SIGNATURES = 'no-signatures'


class SignatureType(StrEnum):
    SIGNATURE = 'signature'
    SEAL = 'seal'
    TIMESTAMP = 'timestamp'


class SignatureLevel(StrEnum):
    QUALIFIED = 'qualified'
    ADVANCED = 'advanced'
    BASIC = 'basic'
    UNKNOWN = 'unknown'


class TrustChainStatus(StrEnum):
    TRUSTED = 'trusted'
    UNTRUSTED = 'untrusted'
    UNAVAILABLE = 'unavailable'
    """Checked against the EU Trusted List, but no confident answer could be
    reached right now (the list data is unreachable or stale). Distinct from
    :attr:`UNKNOWN`, which means "not checked at all"."""
    UNKNOWN = 'unknown'


class TimestampQuality(StrEnum):
    QUALIFIED_TSA = 'qualified_tsa'
    CLAIMED_ONLY = 'claimed_only'
    UNKNOWN = 'unknown'


class RevocationStatus(StrEnum):
    GOOD = 'good'
    """Checked via OCSP and/or CRL; no revocation was found."""
    REVOKED = 'revoked'
    UNAVAILABLE = 'unavailable'
    """A check was attempted but no confident answer could be reached right
    now (the OCSP/CRL endpoint was unreachable or timed out). Distinct from
    :attr:`NOT_CHECKED`, which means no check was attempted at all."""
    NOT_CHECKED = 'not_checked'


@dataclass(frozen=True)
class IntegrityStatus:
    """Result of ByteRange/CMS integrity checking for one signature."""

    intact: bool
    """The signed digest matches the signed byte range of the document."""

    signature_valid: bool
    """The cryptographic signature validates against the signer's certificate."""

    fully_covered: bool
    """The signature covers the entire file, with no unsigned trailing changes."""

    modified_after_signing: bool | None
    """Whether the document was tampered with after this signature was applied.
    Excludes permissible PAdES long-term-archival updates (see
    :attr:`lta_extended`). ``None`` if this could not be determined."""

    lta_extended: bool
    """Whether the only changes after this signature was applied were
    permissible long-term-archival additions (e.g. a document timestamp or
    DSS update per PAdES-LTA). A neutral/positive fact, not a warning."""


@dataclass(frozen=True)
class SignatureItem:
    type: SignatureType
    integrity: IntegrityStatus
    plain_explanation: str
    technical_detail: str | None
    signer_name: str | None = None
    issuing_tsp: str | None = None
    signing_time: datetime | None = None
    timestamp_quality: TimestampQuality = TimestampQuality.UNKNOWN
    level: SignatureLevel = SignatureLevel.UNKNOWN
    trust_chain_status: TrustChainStatus = TrustChainStatus.UNKNOWN
    revocation_status: RevocationStatus = RevocationStatus.NOT_CHECKED


@dataclass(frozen=True)
class VerificationResult:
    verdict: VerificationVerdict
    items: list[SignatureItem] = field(default_factory=list)
    document_sha256: str = ''
    verified_at: datetime | None = None
    trusted_list_status: str = 'not_checked'
