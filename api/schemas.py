"""JSON response shapes. Built directly from the core dataclasses via
Pydantic's ``from_attributes``, so the shape here always mirrors
``eidas_inspect_core.models`` exactly -- no hand-maintained duplicate
field list to drift out of sync.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from eidas_inspect_core import VerificationResult


class IntegrityStatusOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    intact: bool
    signature_valid: bool
    fully_covered: bool
    modified_after_signing: bool | None
    lta_extended: bool


class CertificateDetailsOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    subject_common_name: str | None
    subject_organization: str | None
    issuer_common_name: str | None
    issuer_organization: str | None
    valid_from: datetime
    valid_until: datetime
    serial_number: str


class TrustMatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    territory: str
    territory_name: str
    trust_service_name: str
    tl_location_url: str


class SignatureItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    type: str
    level: str
    integrity: IntegrityStatusOut
    plain_explanation: str
    technical_detail: str | None
    signer_name: str | None
    issuing_tsp: str | None
    signing_time: datetime | None
    timestamp_quality: str
    trust_chain_status: str
    revocation_status: str
    revocation_source: str | None
    verdict_reason: str
    certificate: CertificateDetailsOut | None
    trust_match: TrustMatchOut | None
    ksi_verification_tier: str | None
    ksi_aggregation_time: datetime | None
    ksi_identity_chain: tuple[str, ...] | None


class VerdictBreakdownOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total: int
    confirmed_qualified: int
    confirmed_independent: int
    confirmed_intact: int
    issues: int
    unconfirmed: int
    not_qualified: int


class VerificationResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    verdict: str
    plain_summary: str
    verdict_breakdown: VerdictBreakdownOut | None
    items: list[SignatureItemOut]
    document_sha256: str
    verified_at: datetime | None


def to_response(result: VerificationResult) -> VerificationResultOut:
    return VerificationResultOut.model_validate(result)
