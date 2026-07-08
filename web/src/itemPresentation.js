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
  const secondary =
    item.issuing_tsp && item.issuing_tsp !== item.signer_name
      ? `Certificate issued by ${item.issuing_tsp}`
      : null
  return { icon: IconInfoCircle, tone: TONE.NEUTRAL, text: primary, sub: secondary }
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
