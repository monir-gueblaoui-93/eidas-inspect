import { useState } from 'react'
import { IconChevronDown } from '../icons.jsx'
import Term from './Term.jsx'
import {
  typeDisplay,
  itemTone,
  itemBadge,
  levelDisplay,
  whoDisplay,
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

      <div className="sig-card__grid">
        <Field label="Level" display={level} />
        <Field label="Who" display={whoDisplay(item)} />
        <Field label="Integrity" display={integrityDisplay(item)} />
        <Field label="When" display={whenDisplay(item)} />
        <Field label="Trust chain" display={trustDisplay(item)} />
        <Field label="Revocation" display={revocationDisplay(item)} />
      </div>

      {item.technical_detail && (
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
          {showTechnical && <p className="sig-card__technical-body">{item.technical_detail}</p>}
        </div>
      )}
    </article>
  )
}
