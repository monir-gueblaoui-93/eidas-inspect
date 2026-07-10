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
  IconLink,
  IconShieldCheck,
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
  if (item.type === 'ksi_seal') return { icon: IconLink, label: 'KSI seal', termKey: 'ksiSeal' }
  if (item.type === 'seal') return { icon: IconBuilding, label: 'Seal' }
  if (item.type === 'timestamp') return { icon: IconClock, label: 'Timestamp' }
  return { icon: IconPerson, label: 'Signature' }
}

/** Is this a KSI seal? -- these carry no certificate, no eIDAS level, and no
 * EU Trusted List chain, so the card presents a different set of fields for
 * them (see the KSI-specific display functions below) rather than showing
 * X.509-shaped rows that would always read as empty. */
export function isKsiSeal(item) {
  return item.type === 'ksi_seal'
}

export function itemTone(item) {
  switch (item.verdict_reason) {
    case 'confirmed_qualified':
    case 'confirmed_independent':
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
    case 'confirmed_independent':
      // Deliberately not "Qualified" -- a well-verified KSI seal is a real
      // positive result via a different trust mechanism, not an eIDAS
      // qualification claim. Same green-family weight as "Qualified &
      // confirmed" (see itemTone above), distinct label.
      return 'Independently verified'
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
    return { text: 'Qualified', tone: TONE.TRUSTED, termKey, icon: IconShieldCheck, strong: true }
  }
  if (item.level === 'advanced') return { text: 'Advanced', tone: TONE.NEUTRAL }
  if (item.level === 'basic') return { text: 'Basic', tone: TONE.NOT_TRUSTED, icon: IconAlertTriangle }
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

/** Short, plain-language labels for each KsiVerificationTier -- deliberately
 * distinct from item.plain_explanation (the full sentence shown as the
 * card's lead paragraph): this is the compact, at-a-glance version for the
 * field grid, following the same tier names the backend already committed
 * to a full sentence for (see core's _KSI_TIER_PLAIN_TEXT). */
const KSI_TIER_META = {
  not_verified: {
    icon: IconInfoCircle,
    tone: TONE.NEUTRAL,
    text: 'Not independently verified',
  },
  internal_only: {
    icon: IconAlertTriangle,
    tone: TONE.PARTIAL,
    text: 'Internally consistent only',
  },
  calendar_verified: {
    // tone TRUSTED, not NEUTRAL: core's verdict_reason for this tier is
    // CONFIRMED_INDEPENDENT (a real cryptographic check against the
    // sealing infrastructure's own certificate actually passed), the same
    // trust bucket PUBLICATION_VERIFIED is in -- just a different, weaker
    // independent anchor. Was NEUTRAL before that backend fix landed.
    icon: IconCheckCircle,
    tone: TONE.TRUSTED,
    text: "Checked against the sealer's own certificate",
  },
  publication_verified: {
    icon: IconCheckCircle,
    tone: TONE.TRUSTED,
    text: 'Anchored to a publicly witnessed record',
  },
  broken: {
    icon: IconXCircle,
    tone: TONE.NOT_TRUSTED,
    text: 'Broken',
  },
}

/** Detailed, tier-specific wording for the card's "Verification" grid
 * field -- distinguishes *how* a KSI seal was independently confirmed
 * (calendar cert vs. publication record). See ksiLevelBadgeDisplay below
 * for the separate, deliberately blunter label used in the prominent
 * level-equivalent badge. */
export function ksiTierDisplay(item) {
  return KSI_TIER_META[item.ksi_verification_tier] || {
    icon: IconInfoCircle,
    tone: TONE.NEUTRAL,
    text: 'Unknown',
  }
}

/** KSI's level-equivalent badge -- occupies the same prominent slot
 * levelDisplay's "Qualified"/"Advanced"/"Basic" badge does for an X.509
 * item, but a KSI seal has no eIDAS level at all, so this is a distinct
 * label set, not a re-skin: CALENDAR_VERIFIED/PUBLICATION_VERIFIED both
 * read "Independently verified" (same strong, green-family weight as
 * "Qualified" -- never the word "qualified" itself). The grid's
 * "Verification" field (ksiTierDisplay above) keeps the more detailed,
 * tier-specific wording; this is the blunter, glanceable version. */
const KSI_LEVEL_BADGE_META = {
  not_verified: { icon: IconInfoCircle, tone: TONE.NEUTRAL, text: 'Not yet verified' },
  internal_only: { icon: IconAlertTriangle, tone: TONE.PARTIAL, text: 'Internally consistent only' },
  calendar_verified: {
    icon: IconShieldCheck,
    tone: TONE.TRUSTED,
    text: 'Independently verified',
    strong: true,
  },
  publication_verified: {
    icon: IconShieldCheck,
    tone: TONE.TRUSTED,
    text: 'Independently verified',
    strong: true,
  },
  broken: { icon: IconXCircle, tone: TONE.NOT_TRUSTED, text: 'Broken' },
}

export function ksiLevelBadgeDisplay(item) {
  return (
    KSI_LEVEL_BADGE_META[item.ksi_verification_tier] || {
      icon: IconInfoCircle,
      tone: TONE.NEUTRAL,
      text: 'Unknown',
    }
  )
}

export function ksiSealedDisplay(item) {
  const when = formatWhen(item.ksi_aggregation_time)
  if (!when) return { icon: IconClock, tone: TONE.NEUTRAL, text: 'Not available' }
  return { icon: IconClock, tone: TONE.NEUTRAL, text: when }
}

export function ksiIdentityChainDisplay(item) {
  const chain = item.ksi_identity_chain
  if (!chain || chain.length === 0) {
    return { icon: IconLink, tone: TONE.NEUTRAL, text: 'Not available' }
  }
  return { icon: IconLink, tone: TONE.NEUTRAL, text: chain.join(' → ') }
}

/** A KSI seal's coverage is a /ByteRange check, not the incremental-update
 * diff analysis integrityDisplay's "modified_after_signing" branches are
 * built for -- that field is always null for a KSI item (see
 * SignatureItem's docstring), so reusing integrityDisplay unmodified would
 * show every KSI seal, however strongly verified, as "could not fully
 * confirm the document was unchanged". This reads the fact KSI items
 * actually carry instead. */
export function ksiIntegrityDisplay(item) {
  const integrity = item.integrity
  if (!integrity.intact || !integrity.signature_valid) {
    return { icon: IconXCircle, tone: TONE.NOT_TRUSTED, text: 'Broken — cannot be relied on' }
  }
  if (!integrity.fully_covered) {
    return {
      icon: IconAlertTriangle,
      tone: TONE.PARTIAL,
      text: 'Does not cover the whole document',
    }
  }
  return { icon: IconCheckCircle, tone: TONE.TRUSTED, text: 'Covers the whole document' }
}

export { TONE }
