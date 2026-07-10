import { IconCheckCircle, IconXCircle, IconInfoCircle, IconAlertTriangle } from '../icons.jsx'

const HEADINGS = {
  trusted: 'Fully trusted',
  partial: 'Partially trusted',
  'not-trusted': 'Not trusted',
  'no-signatures': 'No digital signatures found',
}

const TONE_CLASS = {
  trusted: 'trusted',
  partial: 'partial',
  'not-trusted': 'not-trusted',
  'no-signatures': 'neutral',
}

/** Splits "Fully trusted — all 2 signatures are qualified..." into
 * { heading, detail } so the banner doesn't repeat the heading twice
 * (once as heading, once as the first words of the detail line).
 *
 * Deliberately used as the *source of truth* for the heading on
 * trusted/partial verdicts, rather than a static per-verdict label: core's
 * plain_summary itself distinguishes "Fully trusted" (every item is
 * eIDAS-qualified) from a bare "Trusted" (e.g. a KSI-only document,
 * confirmed but never eIDAS-qualified) -- a static HEADINGS lookup keyed
 * only by verdict would silently collapse that distinction back together
 * in the one place users read first. */
function splitSummary(text) {
  const idx = text.indexOf('—')
  if (idx === -1) return { heading: null, detail: text }
  return { heading: text.slice(0, idx).trim(), detail: text.slice(idx + 1).trim() }
}

function partialIcon(breakdown) {
  if (!breakdown) return IconInfoCircle
  if (breakdown.issues > 0) return IconAlertTriangle
  if (breakdown.unconfirmed > 0) return IconInfoCircle
  return IconCheckCircle
}

export default function VerdictBanner({ verdict, plainSummary, breakdown }) {
  const tone = TONE_CLASS[verdict] ?? 'neutral'
  const usesSplitHeading = verdict === 'partial' || verdict === 'trusted'
  const split = usesSplitHeading ? splitSummary(plainSummary) : null
  const heading = split?.heading || HEADINGS[verdict] || plainSummary
  const detail = split ? split.detail : plainSummary

  const Icon =
    verdict === 'trusted'
      ? IconCheckCircle
      : verdict === 'not-trusted'
        ? IconXCircle
        : verdict === 'partial'
          ? partialIcon(breakdown)
          : IconInfoCircle

  return (
    <div className={`verdict-banner verdict-banner--${tone}`} role="status">
      <span className="verdict-banner__icon">
        <Icon size={32} />
      </span>
      <div>
        <p className="verdict-banner__heading">{heading}</p>
        {detail && detail !== heading && <p className="verdict-banner__detail">{detail}</p>}
      </div>
    </div>
  )
}
