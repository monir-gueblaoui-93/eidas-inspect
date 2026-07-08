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

/** Splits "Fully trusted — all 2 signatures are qualified..." into a lead
 * phrase and the rest, so the banner doesn't repeat "Fully trusted" twice
 * (once as heading, once as the first words of the detail line). */
function splitSummary(text) {
  const idx = text.indexOf('—')
  if (idx === -1) return text
  return text.slice(idx + 1).trim()
}

function partialIcon(breakdown) {
  if (!breakdown) return IconInfoCircle
  if (breakdown.issues > 0) return IconAlertTriangle
  if (breakdown.unconfirmed > 0) return IconInfoCircle
  return IconCheckCircle
}

export default function VerdictBanner({ verdict, plainSummary, breakdown }) {
  const tone = TONE_CLASS[verdict] ?? 'neutral'
  const heading = HEADINGS[verdict] ?? plainSummary
  const detail = verdict === 'partial' || verdict === 'trusted' ? splitSummary(plainSummary) : plainSummary

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
      <Icon size={32} />
      <div>
        <p className="verdict-banner__heading">{heading}</p>
        {detail && detail !== heading && <p className="verdict-banner__detail">{detail}</p>}
      </div>
    </div>
  )
}
