"""Subprocess wrapper around Guardtime's official ``ksi-tool`` CLI
(Apache-2.0, github.com/guardtime/ksi-tool) -- KSI's own reference
verification engine.

Mirrors this project's established rule for pyHanko: never reimplement a
trust engine's cryptography ourselves. pyHanko does PAdES/CMS validation;
``ksi-tool`` does KSI's hash-chain and publications-file verification.
This module owns strictly the subprocess boundary and output parsing; all
PDF-container-level work (finding the ``/FT /KSI`` field, extracting
``/ByteRange`` bytes) stays in ``verify.py``.

Confirmed empirically against a real Guardtime-issued KSI signature
(github.com/guardtime/ksi-pdf-verifier's ``demo/signed.pdf``) before
writing this module -- see PROGRESS.md's KSI research notes for the
exact commands run and output observed. In particular: ``--dump``'s
"Final result:" line uses exactly three tokens (``OK``, ``NA``, ``FAIL``)
-- not the "FAILED" spelling the man page's prose uses -- confirmed by
deliberately tampering a document hash and reading the real output
rather than guessing.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum

DEFAULT_BINARY = 'ksi'
DEFAULT_TIMEOUT_SECONDS = 10.0
"""Hard per-invocation timeout -- an unreachable/slow extender or
publications-file host must never stall verification, same rule as the
OCSP/CRL/Trusted-List fetch timeouts elsewhere in this project."""

GUARDTIME_PUBLICATIONS_FILE_URL = 'http://verify.guardtime.com/ksi-publications.bin'
"""Guardtime's own publicly hosted publications file. ``ksi-tool`` fetches
and verifies it directly when given a URL via ``-P`` -- no separate
fetch/cache/refresh layer is implemented on our side (unlike the EU
Trusted List's ``TrustListCache``): letting ``ksi-tool`` own this mirrors
the same "wrap the trusted engine" rule, and the publications file is
tiny and infrequently updated, so a live fetch per verification is cheap
enough not to warrant one."""

GUARDTIME_PUBLICATIONS_CERT_CONSTRAINT = 'E=publications@guardtime.com'
"""The publications file is itself signed by a certificate issued (by a
publicly trusted CA) to this e-mail address -- confirmed via Guardtime's
own KSI Service Disclosure Statement. Required by ``ksi-tool`` as the
trust-anchor constraint for verifying the publications file's own PKI
signature."""


class KsiCheckOutcome(StrEnum):
    """The three real result tokens ``ksi-tool``'s own ``--dump`` output
    uses for a completed verification (confirmed empirically: ``OK``,
    ``NA``, ``FAIL``), plus a fourth for when the tool didn't reach a
    verification verdict at all (bad invocation, network error, I/O
    error, ...) -- a different failure mode from "verification failed",
    and one that must never be silently conflated with it."""

    OK = 'ok'
    NA = 'na'
    FAIL = 'fail'
    TOOL_ERROR = 'tool_error'


@dataclass(frozen=True)
class KsiCheckResult:
    outcome: KsiCheckOutcome
    detail: str | None
    """The specific error/rule text from ksi-tool's own output, if any --
    for the technical drawer. ``None`` for a clean OK."""
    aggregation_time: datetime | None
    identity_chain: tuple[str, ...] | None


def _default_invoke(
    args: list[str], timeout_seconds: float
) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, capture_output=True, text=True, timeout=timeout_seconds, check=False
    )


@dataclass(frozen=True)
class KsiToolRunner:
    """Injectable subprocess boundary -- mirrors ``RevocationFetchers``'
    dependency-injection pattern (see ``.revocation``) for the same
    reason: tests stay fully offline by injecting a stub ``invoke``,
    never shelling out to a real binary or hitting a real network
    endpoint."""

    binary_path: str = DEFAULT_BINARY
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    invoke: Callable[[list[str], float], subprocess.CompletedProcess] = _default_invoke

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        full_args = [self.binary_path, *args]
        try:
            return self.invoke(full_args, self.timeout_seconds)
        except (OSError, subprocess.TimeoutExpired) as e:
            return subprocess.CompletedProcess(
                args=full_args, returncode=-1, stdout='', stderr=str(e)
            )

    def verify_internal(self, signature_path: str, data_path: str) -> KsiCheckResult:
        """Internal consistency, bound to this specific document's hash
        (via ``-f``) -- deliberately always document-bound, even for the
        "internal" tier: without it, a genuine-but-unrelated KSI token
        pasted onto a tampered document would still read as "internally
        consistent", which would be true but actively misleading for a
        per-document seal verifier."""
        result = self._run(
            'verify', '--ver-int', '-i', signature_path, '-f', data_path, '--dump'
        )
        return _parse_dump(result)

    def verify_publication_based(
        self,
        signature_path: str,
        data_path: str,
        publications_file_url: str = GUARDTIME_PUBLICATIONS_FILE_URL,
        cert_constraint: str = GUARDTIME_PUBLICATIONS_CERT_CONSTRAINT,
    ) -> KsiCheckResult:
        """Publication-based ("extended") verification. Deliberately does
        *not* pass ``-x`` (permit automatic extending): extending talks to
        Guardtime's authenticated Extender service, which is out of scope
        for an anonymous public tool (see PROGRESS.md) -- an unextended
        signature should read as NA here, not silently trigger a live
        extend call."""
        result = self._run(
            'verify',
            '--ver-pub',
            '-i',
            signature_path,
            '-f',
            data_path,
            '-P',
            publications_file_url,
            '--cnstr',
            cert_constraint,
            '--dump',
        )
        return _parse_dump(result)


_FINAL_RESULT_RE = re.compile(r'Final result:\s*\n\s*(OK|NA|FAIL)\b\s*:?\s*(.*)')
_SIGNING_TIME_RE = re.compile(r'Signing time:\s*\((\d+)\)')
_IDENTITY_RE = re.compile(r"Client ID:\s*'([^']*)',\s*Machine ID:\s*'([^']*)'")

_OUTCOME_BY_TOKEN = {
    'OK': KsiCheckOutcome.OK,
    'NA': KsiCheckOutcome.NA,
    'FAIL': KsiCheckOutcome.FAIL,
}


def _parse_dump(result: subprocess.CompletedProcess) -> KsiCheckResult:
    stdout = result.stdout or ''

    aggregation_time = None
    time_match = _SIGNING_TIME_RE.search(stdout)
    if time_match:
        aggregation_time = datetime.fromtimestamp(
            int(time_match.group(1)), tz=timezone.utc
        )

    identity_chain = tuple(
        f'{client_id}:{machine_id}' if client_id else machine_id
        for client_id, machine_id in _IDENTITY_RE.findall(stdout)
    ) or None

    final_match = _FINAL_RESULT_RE.search(stdout)
    if final_match is None:
        # The tool didn't get far enough to produce a verification
        # verdict at all -- bad invocation, network error, I/O error, a
        # crypto-level failure verifying the publications file itself,
        # etc. (see ksi(1)'s EXIT STATUS: anything other than 0 or 6).
        # There's no rule-level detail to show, so surface whatever the
        # tool printed instead.
        detail = (result.stderr or stdout or 'ksi-tool produced no output').strip()
        return KsiCheckResult(
            KsiCheckOutcome.TOOL_ERROR, detail or None, aggregation_time, identity_chain
        )

    token, rest = final_match.group(1), final_match.group(2).strip()
    outcome = _OUTCOME_BY_TOKEN[token]
    # "No verification errors." on a clean OK isn't a meaningful detail --
    # only NA/FAIL carry an actual rule/error worth surfacing.
    detail = rest if outcome is not KsiCheckOutcome.OK and rest else None
    return KsiCheckResult(outcome, detail, aggregation_time, identity_chain)
