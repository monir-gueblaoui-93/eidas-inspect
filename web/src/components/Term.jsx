import { useId, useState } from 'react'
import { GLOSSARY } from '../glossary.js'
import { IconInfoCircle } from '../icons.jsx'

/** Inline glossary expandable: click the term to reveal a plain-language
 * explanation right below it, in normal document flow (no positioning
 * tricks that break on mobile). */
export default function Term({ id, children }) {
  const entry = GLOSSARY[id]
  const [open, setOpen] = useState(false)
  const panelId = useId()

  if (!entry) return children

  return (
    <span className="term">
      <button
        type="button"
        className="term-trigger"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
      >
        {children}
        <IconInfoCircle size={14} />
      </button>
      {open && (
        <span id={panelId} className="term-panel" role="note">
          {entry.body}
        </span>
      )}
    </span>
  )
}
