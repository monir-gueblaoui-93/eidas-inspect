/**
 * Pure mapping from a raw `SignatureItemOut` (see api/schemas.py) to
 * plain-language display data. Kept separate from the card component so the
 * "what does this JSON mean" logic is in one legible place.
 */
import {
  IconPerson,
  IconBuilding,
  IconClock,
  IconCheckCircle,
  IconAlertTriangle,
  IconXCircle,
  IconInfoCircle,
} from './icons.jsx'

const TONE = {
  TRUSTED: 'trusted',
  PARTIAL: 'partial',
  NOT_TRUSTED: 'not-trusted',
  NEUTRAL: 'neutral',
}

export function formatWhen(isoString) {
  if (!isoString) return null
  try {
    return new Date(isoString).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  } catch {
    return isoString
  }
}

export function typeDisplay(item) {
  if (item.type === 'seal') return { icon: IconBuilding, label: 'Seal' }
  if (item.type === 'timestamp') return { icon: IconClock, label: 'Timestamp' }
  return { icon: IconPerson, label: 'Signature' }
}

export function itemTone(item) {
  switch (item.verdict_reason) {
    case 'confirmed_qualified':
      return TONE.TRUSTED
    case 'broken':
    case 'tampered':
    case 'revoked':
    case 'not_trusted':
      return TONE.NOT_TRUSTED
    case 'unconfirmed':
      return TONE.PARTIAL
    default:
      return TONE.NEUTRAL
  }
}

export function itemBadge(item) {
  switch (item.verdict_reason) {
    case 'confirmed_qualified':
      return 'Qualified & confirmed'
    case 'broken':
      return 'Broken'
    case 'tampered':
      return 'Tampered'
    case 'revoked':
      return 'Revoked'
    case 'not_trusted':
      return 'Not on Trusted List'
    case 'unconfirmed':
      return 'Unconfirmed'
    default:
      return 'Valid, not qualified'
  }
}

export function levelDisplay(item) {
  if (item.level === 'qualified') {
    const termKey = item.type === 'seal' ? 'qseal' : item.type === 'signature' ? 'qes' : 'qualified'
    return { text: 'Qualified', tone: TONE.TRUSTED, termKey }
  }
  if (item.level === 'advanced') return { text: 'Advanced', tone: TONE.NEUTRAL }
  if (item.level === 'basic') return { text: 'Basic', tone: TONE.NOT_TRUSTED }
  return { text: 'Unknown', tone: TONE.NEUTRAL }
}

export function whoDisplay(item) {
  const verb = item.type === 'seal' ? 'Sealed' : item.type === 'timestamp' ? 'Issued' : 'Signed'
  const primary = item.signer_name
    ? `${verb} by ${item.signer_name}`
    : item.type === 'timestamp'
      ? 'Timestamp authority not identified'
      : 'Signer not identified'
  // Who issued the certificate now has its own prominent row (see
  // issuerDisplay) rather than being buried here as a secondary line.
  return { icon: IconInfoCircle, tone: TONE.NEUTRAL, text: primary }
}

/** The certificate issuer, promoted to its own prominent card element per
 * user feedback that it was too easy to miss as a "Who" sub-line. */
export function issuerDisplay(item) {
  return {
    text: item.issuing_tsp ? `Issued by ${item.issuing_tsp}` : 'Issuer not identified',
    // Matches the card's own "Qualified & confirmed" badge condition
    // (itemBadge/itemTone) so a standalone qualified timestamp gets the
    // same affirmation a qualified signature/seal does -- its "qualified"
    // signal lives in timestamp_quality rather than level, so gating on
    // level alone would silently skip every timestamp item.
    onTrustedList: item.verdict_reason === 'confirmed_qualified',
  }
}

/** Deep link to the EU's official eIDAS Dashboard TL browser page for one
 * territory -- confirmed live (2026) at
 * eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls/tl/{code},
 * e.g. .../tl/FR for France. Only meaningful when a trust_match exists. */
export function eidasDashboardUrl(territory) {
  return `https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls/tl/${territory}`
}

function pickPrimarySecondary(primaryValue, secondaryValue) {
  const primary = primaryValue || secondaryValue || null
  const secondary = secondaryValue && secondaryValue !== primary ? secondaryValue : null
  return { primary, secondary }
}

/** Structured certificate facts for the "Certificate" section -- subject
 * fields lead with whichever is more meaningful for the item's type (an
 * organization's name for a seal, a person's name for a signature). */
export function certificateDisplay(item) {
  const cert = item.certificate
  if (!cert) return null

  const isOrgLed = item.type === 'seal'
  const subject = isOrgLed
    ? pickPrimarySecondary(cert.subject_organization, cert.subject_common_name)
    : pickPrimarySecondary(cert.subject_common_name, cert.subject_organization)
  const issuer = pickPrimarySecondary(cert.issuer_common_name, cert.issuer_organization)

  return {
    subject: { primary: subject.primary || 'Not available', secondary: subject.secondary },
    issuer: { primary: issuer.primary || 'Not available', secondary: issuer.secondary },
    validFrom: formatWhen(cert.valid_from),
    validUntil: formatWhen(cert.valid_until),
    serialNumber: cert.serial_number,
  }
}

export function integrityDisplay(item) {
  const integrity = item.integrity
  if (!integrity.intact || !integrity.signature_valid) {
    return {
      icon: IconXCircle,
      tone: TONE.NOT_TRUSTED,
      text: 'Broken — cannot be relied on',
    }
  }
  if (integrity.modified_after_signing === true) {
    return {
      icon: IconAlertTriangle,
      tone: TONE.NOT_TRUSTED,
      text: 'Changed after signing',
    }
  }
  if (integrity.modified_after_signing === null) {
    return {
      icon: IconInfoCircle,
      tone: TONE.PARTIAL,
      text: 'Could not fully confirm the document was unchanged',
    }
  }
  if (integrity.lta_extended) {
    return {
      icon: IconCheckCircle,
      tone: TONE.TRUSTED,
      text: 'Intact',
      sub: 'Extended afterwards for long-term validation — a normal, protective update, not tampering.',
    }
  }
  return {
    icon: IconCheckCircle,
    tone: TONE.TRUSTED,
    text: 'Intact — not tampered with',
  }
}

export function whenDisplay(item) {
  const when = formatWhen(item.signing_time)
  if (!when) {
    return { icon: IconClock, tone: TONE.NEUTRAL, text: 'Signing time not available' }
  }
  if (item.timestamp_quality === 'qualified_tsa') {
    return {
      icon: IconCheckCircle,
      tone: TONE.TRUSTED,
      text: when,
      sub: 'Confirmed by a qualified timestamp',
      termKey: 'timestamp',
    }
  }
  if (item.timestamp_quality === 'claimed_only') {
    return {
      icon: IconAlertTriangle,
      tone: TONE.PARTIAL,
      text: when,
      sub: "The signer's own claimed time — not independently verified",
    }
  }
  return {
    icon: IconInfoCircle,
    tone: TONE.NEUTRAL,
    text: when,
    sub:
      item.type === 'timestamp'
        ? "Cryptographically verified, but the issuing authority isn't confirmed as qualified"
        : 'Backed by a verified timestamp, but the issuing authority isn\'t confirmed as qualified',
  }
}

export function trustDisplay(item) {
  switch (item.trust_chain_status) {
    case 'trusted':
      return {
        icon: IconCheckCircle,
        tone: TONE.TRUSTED,
        text: 'Confirmed on the EU Trusted List',
        termKey: 'trustedList',
      }
    case 'untrusted':
      return {
        icon: IconXCircle,
        tone: TONE.NOT_TRUSTED,
        text: 'Not found on the EU Trusted List',
        termKey: 'trustedList',
      }
    case 'unavailable':
      return {
        icon: IconAlertTriangle,
        tone: TONE.PARTIAL,
        text: "Couldn't be confirmed right now",
        sub: 'EU Trusted List data was unreachable or stale at verification time.',
        termKey: 'trustedList',
      }
    default:
      return { icon: IconInfoCircle, tone: TONE.NEUTRAL, text: 'Not checked' }
  }
}

export function revocationDisplay(item) {
  const sourceLabel =
    item.revocation_source === 'embedded'
      ? "Confirmed via the document's own signing-time record"
      : item.revocation_source === 'live'
        ? 'Confirmed via a live check just now'
        : null

  switch (item.revocation_status) {
    case 'good':
      return { icon: IconCheckCircle, tone: TONE.TRUSTED, text: 'Not revoked', sub: sourceLabel }
    case 'revoked':
      return {
        icon: IconXCircle,
        tone: TONE.NOT_TRUSTED,
        text: 'Revoked',
        sub: 'See technical details below.',
      }
    case 'unavailable':
      return {
        icon: IconAlertTriangle,
        tone: TONE.PARTIAL,
        text: "Couldn't be confirmed right now",
        sub: 'The revocation endpoint was unreachable or timed out.',
      }
    default:
      return { icon: IconInfoCircle, tone: TONE.NEUTRAL, text: 'Not checked' }
  }
}

export { TONE }
