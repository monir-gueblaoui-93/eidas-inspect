import { useState } from 'react'
import { IconChevronDown, IconBuilding, IconCheckCircle, IconExternalLink } from '../icons.jsx'
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

export default function SignatureCard({ item }) {
  const tone = itemTone(item)
  const type = typeDisplay(item)
  const TypeIcon = type.icon
  const [showTechnical, setShowTechnical] = useState(tone === 'not-trusted' || tone === 'partial')

  const level = levelDisplay(item)

  return (
    <article className={`sig-card sig-card--${tone}`}>
      <header className="sig-card__header">
        <span className="sig-card__type">
          <TypeIcon size={22} />
          {type.label}
        </span>
        <span className={`sig-card__badge sig-card__badge--${tone}`}>{itemBadge(item)}</span>
      </header>

      <p className="sig-card__lead">{item.plain_explanation}</p>

      <IssuerRow item={item} />

      <div className="sig-card__grid">
        <Field label="Level" display={level} />
        <Field label="Who" display={whoDisplay(item)} />
        <Field label="Integrity" display={integrityDisplay(item)} />
        <Field label="When" display={whenDisplay(item)} />
        <Field label="Trust chain" display={trustDisplay(item)} />
        <Field label="Revocation" display={revocationDisplay(item)} />
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
    </article>
  )
}
