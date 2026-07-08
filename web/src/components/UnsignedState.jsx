import { IconInfoCircle } from '../icons.jsx'

export default function UnsignedState({ onReset }) {
  return (
    <section className="unsigned-state">
      <div className="unsigned-state__icon">
        <IconInfoCircle size={32} />
      </div>
      <h2>This document contains no digital signatures</h2>
      <p>
        A scanned image of a handwritten signature, or a signature drawn in a PDF editor,
        is <strong>not</strong> a digital signature — it carries no cryptographic proof and
        can't be verified this way.
      </p>
      <div className="unsigned-state__suggestions">
        <p>To get a document properly signed, you could:</p>
        <ul>
          <li>Use a qualified electronic signature (QES) service — most banks, notaries, and business platforms in the EU offer one.</li>
          <li>Ask your organization's IT or legal team which signing provider they're already accredited with.</li>
          <li>Look for your country's government-backed eID signing portal, if one is available.</li>
        </ul>
      </div>
      <button type="button" className="btn btn--primary" onClick={onReset}>
        Check another document
      </button>
    </section>
  )
}
