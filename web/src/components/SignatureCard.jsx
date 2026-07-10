import { useState } from 'react'
import {
  IconChevronDown,
  IconBuilding,
  IconCheckCircle,
  IconXCircle,
  IconExternalLink,
} from '../icons.jsx'
import Term from './Term.jsx'
import CertificateSection from './CertificateSection.jsx'
import {
  typeDisplay,
  itemTone,
  itemBadge,
  levelDisplay,
  whoDisplay,
  issuerDisplay,
  eidasDashboardUrl,
  integrityDisplay,
  whenDisplay,
  trustDisplay,
  revocationDisplay,
  isKsiSeal,
  ksiTierDisplay,
  ksiLevelBadgeDisplay,
  ksiSealedDisplay,
  ksiIdentityChainDisplay,
  ksiIntegrityDisplay,
} from '../itemPresentation.js'

function Field({ label, display }) {
  const Icon = display.icon
  return (
    <div className="sig-field">
      <span className="sig-field__label">{label}</span>
      <span className={`sig-field__value sig-field__value--${display.tone}`}>
        {Icon && <Icon size={16} />}
        <span>
          {display.termKey ? <Term id={display.termKey}>{display.text}</Term> : display.text}
        </span>
      </span>
      {display.sub && <span className="sig-field__sub">{display.sub}</span>}
    </div>
  )
}

/** The prominent level/tier badge -- "Qualified", "Independently verified",
 * etc. Occupies the slot tasks 3+5 both point at: the strongest positive
 * result (Qualified for X.509, Independently verified for a
 * well-verified KSI seal) gets the punchier --strong fill; everything
 * else gets the plain tone-colored pill. */
function LevelBadge({ display }) {
  const Icon = display.icon
  return (
    <span
      className={`sig-card__level-badge sig-card__level-badge--${display.tone}${
        display.strong ? ' sig-card__level-badge--strong' : ''
      }`}
    >
      {Icon && <Icon size={15} />}
      {display.termKey ? <Term id={display.termKey}>{display.text}</Term> : display.text}
    </span>
  )
}

function IssuerRow({ item }) {
  const issuer = issuerDisplay(item)
  const trustMatch = item.trust_match

  return (
    <div className="issuer-row">
      <IconBuilding size={20} />
      <div className="issuer-row__body">
        <span className="issuer-row__text">{issuer.text}</span>
        {issuer.onTrustedList && (
          <div className="issuer-row__trust">
            <span className="issuer-row__badge">
              <IconCheckCircle size={13} />
              <Term id="trustedList">On the EU Trusted List</Term>
            </span>
            {trustMatch && (
              <a
                className="issuer-row__verify-link"
                href={eidasDashboardUrl(trustMatch.territory)}
                target="_blank"
                rel="noopener noreferrer"
              >
                Verify it yourself
                <IconExternalLink size={13} />
                <span className="visually-hidden">(opens in a new tab)</span>
              </a>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

/** @param {object} props
 * @param {boolean} [props.collapsible] -- when true (multi-item documents),
 * the card starts as a compact, clickable summary row and only shows its
 * full body once expanded. When false (a single-item document), the full
 * card always renders -- the identity strip below still applies, so level
 * and signer stay prominent either way, just without a collapse control.
 * @param {boolean} [props.dense] -- true for high-count documents (see
 * `COLLAPSE_THRESHOLD` in ResultView.jsx): renders as a compact, full-width
 * list row instead of a card-grid tile, and expand state is controlled
 * externally (via `expanded`/`onToggle`) so a document-level "expand all"
 * control can drive every row at once.
 * @param {boolean} [props.expanded] -- when provided, the card's expand
 * state is controlled by the parent instead of managed internally.
 * @param {() => void} [props.onToggle] -- required alongside `expanded`. */
export default function SignatureCard({ item, collapsible = false, dense = false, expanded: expandedProp, onToggle }) {
  const tone = itemTone(item)
  const type = typeDisplay(item)
  const TypeIcon = type.icon
  const isKsi = isKsiSeal(item)

  const levelBadge = isKsi ? ksiLevelBadgeDisplay(item) : levelDisplay(item)
  const signerText = isKsi ? null : whoDisplay(item).text
  const isValid = item.integrity.intact && item.integrity.signature_valid

  // Problems surface immediately even in a collapsed multi-item list --
  // same "don't make the user go looking for bad news" rule the technical
  // drawer below already follows. In `dense` mode this default is overridden
  // by the controlled `expanded` prop instead (see ResultView.jsx): with
  // many items, EVERY row starts collapsed regardless of tone, and the
  // tone-colored badge/validity-tick on the row itself is what surfaces a
  // problem without forcing a wall of expanded cards back onto the screen.
  const needsAttention = tone === 'not-trusted' || tone === 'partial'
  const isControlled = expandedProp !== undefined
  const [internalExpanded, setInternalExpanded] = useState(!collapsible || needsAttention)
  const [showTechnical, setShowTechnical] = useState(needsAttention)

  const expanded = isControlled ? expandedProp : internalExpanded
  const toggleExpanded = isControlled ? onToggle : () => setInternalExpanded((v) => !v)

  const showBody = !collapsible || expanded
  const SummaryTag = collapsible ? 'button' : 'div'
  const summaryLabel = `${type.label}: ${levelBadge.text}${signerText ? `, ${signerText}` : ''}, ${
    isValid ? 'valid' : 'invalid'
  } — ${expanded ? 'collapse' : 'expand'} details`

  return (
    <article
      className={`sig-card sig-card--${tone}${collapsible ? ' sig-card--collapsible' : ''}${
        collapsible && expanded ? ' sig-card--expanded' : ''
      }${dense ? ' sig-card--dense' : ''}`}
    >
      <SummaryTag
        type={collapsible ? 'button' : undefined}
        className="sig-card__summary"
        aria-expanded={collapsible ? expanded : undefined}
        aria-label={collapsible ? summaryLabel : undefined}
        title={dense && signerText ? signerText : undefined}
        onClick={collapsible ? toggleExpanded : undefined}
      >
        <span className="sig-card__type">
          <TypeIcon size={22} />
          {type.termKey ? <Term id={type.termKey}>{type.label}</Term> : type.label}
        </span>
        <LevelBadge display={levelBadge} />
        {signerText && <span className="sig-card__summary-signer">{signerText}</span>}
        <span className={`sig-card__validity sig-card__validity--${isValid ? 'valid' : 'invalid'}`}>
          {isValid ? <IconCheckCircle size={14} /> : <IconXCircle size={14} />}
          {isValid ? 'Valid' : 'Invalid'}
        </span>
        <span className={`sig-card__badge sig-card__badge--${tone}`}>{itemBadge(item)}</span>
        {collapsible && (
          <IconChevronDown size={18} className={`sig-card__summary-chevron${expanded ? ' is-open' : ''}`} />
        )}
      </SummaryTag>

      {showBody && (
        <div className="sig-card__body">
          <p className="sig-card__lead">{item.plain_explanation}</p>

          {!isKsi && <IssuerRow item={item} />}

          <div className="sig-card__grid">
            {isKsi ? (
              <>
                <Field label="Verification" display={ksiTierDisplay(item)} />
                <Field label="Sealed" display={ksiSealedDisplay(item)} />
                <Field label="Integrity" display={ksiIntegrityDisplay(item)} />
                <Field label="Identity chain" display={ksiIdentityChainDisplay(item)} />
              </>
            ) : (
              <>
                <Field label="Integrity" display={integrityDisplay(item)} />
                <Field label="When" display={whenDisplay(item)} />
                <Field label="Trust chain" display={trustDisplay(item)} />
                <Field label="Revocation" display={revocationDisplay(item)} />
              </>
            )}
          </div>

          <CertificateSection item={item} />

          {(item.technical_detail || item.certificate) && (
            <div className="sig-card__technical">
              <button
                type="button"
                className="sig-card__technical-toggle"
                aria-expanded={showTechnical}
                onClick={() => setShowTechnical((v) => !v)}
              >
                <IconChevronDown size={16} className={showTechnical ? 'is-open' : ''} />
                Technical details
              </button>
              {showTechnical && (
                <div className="sig-card__technical-body">
                  {item.technical_detail && <p>{item.technical_detail}</p>}
                  {item.certificate && (
                    <p className="sig-card__technical-line">
                      Serial number: <code>{item.certificate.serial_number}</code>
                    </p>
                  )}
                  {item.trust_match && (
                    <p className="sig-card__technical-line">
                      Trusted list source: <code>{item.trust_match.tl_location_url}</code>
                    </p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </article>
  )
}
