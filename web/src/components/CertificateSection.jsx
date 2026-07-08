import { certificateDisplay } from '../itemPresentation.js'

/** Structured certificate facts, visible by default (no extra expand/collapse
 * of its own) -- the serial number is the one properly technical fact, and
 * it lives in the card's existing technical-details drawer instead. */
export default function CertificateSection({ item }) {
  const cert = certificateDisplay(item)
  if (!cert) return null

  return (
    <div className="cert-section">
      <p className="cert-section__title">Certificate</p>
      <dl className="cert-section__list">
        <div className="cert-section__row">
          <dt>Subject</dt>
          <dd>
            {cert.subject.primary}
            {cert.subject.secondary && (
              <span className="cert-section__sub"> ({cert.subject.secondary})</span>
            )}
          </dd>
        </div>
        <div className="cert-section__row">
          <dt>Issuer</dt>
          <dd>
            {cert.issuer.primary}
            {cert.issuer.secondary && (
              <span className="cert-section__sub"> ({cert.issuer.secondary})</span>
            )}
          </dd>
        </div>
        <div className="cert-section__row">
          <dt>Valid</dt>
          <dd>
            {cert.validFrom} – {cert.validUntil}
          </dd>
        </div>
      </dl>
    </div>
  )
}
