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


class VerdictBreakdownOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total: int
    confirmed_qualified: int
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
