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


class VerdictReason(StrEnum):
    """Why one :class:`SignatureItem` counted the way it did towards the
    document-level :class:`VerificationVerdict`. Exposed on every item so a
    UI can render a banner explanation (and per-item badges) without
    re-deriving the classification rules in ``_overall_verdict``."""

    CONFIRMED_QUALIFIED = 'confirmed_qualified'
    """Intact, valid, not tampered, not revoked, qualified, and the issuer
    is confirmed on the EU Trusted List. The "fully green" case."""

    BROKEN = 'broken'
    """Cryptographic integrity failed (bad digest or signature)."""

    TAMPERED = 'tampered'
    """The document was changed after this item was applied, beyond what
    PAdES-LTA permits."""

    REVOKED = 'revoked'
    """The certificate has been revoked."""

    NOT_TRUSTED = 'not_trusted'
    """Otherwise clean, but the issuer was confirmed *not* to be a granted
    qualified service on the EU Trusted List -- a real, known fact, not an
    uncertainty."""

    UNCONFIRMED = 'unconfirmed'
    """Otherwise clean and claims to be qualified, but that claim could not
    be confirmed right now (Trusted List or revocation data unavailable, or
    revocation was never checked). An honest gap, not a known problem."""

    NOT_QUALIFIED = 'not_qualified'
    """Otherwise clean, but does not claim qualified status at all (an
    ordinary advanced signature/seal, or an unconfirmed timestamp). Not a
    problem and not an uncertainty -- simply not qualified."""


@dataclass(frozen=True)
class VerdictBreakdown:
    """Aggregate counts behind the document-level verdict, so a UI can
    render banner detail without re-counting :attr:`SignatureItem.verdict_reason`
    itself."""

    total: int
    confirmed_qualified: int
    issues: int
    unconfirmed: int
    not_qualified: int


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
    verdict_reason: VerdictReason = VerdictReason.NOT_QUALIFIED


@dataclass(frozen=True)
class VerificationResult:
    verdict: VerificationVerdict
    items: list[SignatureItem] = field(default_factory=list)
    document_sha256: str = ''
    verified_at: datetime | None = None
    plain_summary: str = ''
    """Document-level banner text for the verdict, e.g. "Fully trusted --
    all 2 signatures are qualified and intact." No legalese."""
    verdict_breakdown: VerdictBreakdown | None = None
    """Aggregate counts behind :attr:`verdict`. ``None`` only for
    :attr:`VerificationVerdict.NO_SIGNATURES`, where there is nothing to
    count."""
