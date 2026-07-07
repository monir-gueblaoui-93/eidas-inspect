"""qcStatements classification per ETSI EN 319 412-5.

pyHanko already ships correct ASN.1 definitions for the qcStatements
certificate extension (RFC 3739 / ETSI EN 319 412-5) as part of its AdES
support, so we reuse its low-level extraction (``get_qc_statements``) rather
than re-deriving the same OID table. What's ours: reducing that raw
statement list down to the three signals eidas-inspect classifies on
(QcCompliance, QcSSCD, QcType), tolerating malformed/ambiguous real-world
certificates instead of raising.
"""

from dataclasses import dataclass, field

from asn1crypto import x509
from pyhanko.sign.ades.qualified_asn1 import get_qc_statements

_QC_TYPE_NAMES = {
    'qct_esign': 'esign',
    'qct_eseal': 'eseal',
    'qct_web': 'web',
}


@dataclass(frozen=True)
class QcStatements:
    """The subset of a certificate's qcStatements this project classifies on."""

    qc_compliance: bool = False
    """QcCompliance is asserted: the CA declares this a qualified certificate."""

    qc_sscd: bool = False
    """QcSSCD is asserted: the private key is declared to reside in a
    qualified signature/seal creation device."""

    qc_types: frozenset[str] = field(default_factory=frozenset)
    """QcType values asserted, a subset of {'esign', 'eseal', 'web'}.
    Empty if the QcType statement is absent, malformed, or unrecognized."""


def extract_qc_statements(cert: x509.Certificate) -> QcStatements:
    """Read the qcStatements extension from a certificate, if present.

    Malformed or unrecognized statement content is treated as absent rather
    than raising: sloppy real-world certificates must not crash
    classification, they just don't get credit for the ambiguous statement.
    """
    qc_compliance = False
    qc_sscd = False
    qc_types: set[str] = set()

    try:
        statements = get_qc_statements(cert)
    except ValueError:
        return QcStatements()

    for statement in statements:
        try:
            statement_name = statement['statement_id'].native
        except ValueError:
            continue

        if statement_name == 'qc_compliance':
            qc_compliance = True
        elif statement_name == 'qc_sscd':
            qc_sscd = True
        elif statement_name == 'qc_type':
            try:
                type_names = [t.native for t in statement['statement_info']]
            except (ValueError, TypeError):
                continue
            qc_types.update(
                _QC_TYPE_NAMES[name]
                for name in type_names
                if name in _QC_TYPE_NAMES
            )

    return QcStatements(
        qc_compliance=qc_compliance,
        qc_sscd=qc_sscd,
        qc_types=frozenset(qc_types),
    )
