import { useState } from 'react'
import VerdictBanner from './VerdictBanner.jsx'
import SignatureCard from './SignatureCard.jsx'
import UnsignedState from './UnsignedState.jsx'
import DownloadReportButton from './DownloadReportButton.jsx'
import { IconRotate, IconChevronDown } from '../icons.jsx'

// Above this many items, a side-by-side card grid (or a wall of expanded
// cards) stops being scannable -- a real 8+-signer contract is the case
// this was built for. At or below it, a lone signature or a small 2-3
// signer document still reads cleanly as full cards with nothing to scan
// past, so they keep the previous expanded-by-default behavior.
const COLLAPSE_THRESHOLD = 3

export default function ResultView({ result, onReset }) {
  const items = result.items
  const dense = result.verdict !== 'no-signatures' && items.length > COLLAPSE_THRESHOLD
  // Every row starts collapsed in dense mode (see SignatureCard's `dense`
  // doc comment) -- this Set holds which indices have been expanded since.
  const [expandedIndices, setExpandedIndices] = useState(() => new Set())

  if (result.verdict === 'no-signatures') {
    return <UnsignedState onReset={onReset} />
  }

  const toggleOne = (index) => {
    setExpandedIndices((prev) => {
      const next = new Set(prev)
      if (next.has(index)) next.delete(index)
      else next.add(index)
      return next
    })
  }

  const allExpanded = dense && expandedIndices.size === items.length
  const toggleAll = () => setExpandedIndices(allExpanded ? new Set() : new Set(items.map((_, i) => i)))

  return (
    <section className="result-view">
      <VerdictBanner
        verdict={result.verdict}
        plainSummary={result.plain_summary}
        breakdown={result.verdict_breakdown}
      />

      {dense && (
        <div className="result-view__list-controls">
          <span className="result-view__count">{items.length} items</span>
          <button type="button" className="result-view__toggle-all" onClick={toggleAll}>
            <IconChevronDown size={14} className={allExpanded ? 'is-open' : ''} />
            {allExpanded ? 'Collapse all' : 'Expand all'}
          </button>
        </div>
      )}

      <div
        className={`result-view__cards${items.length > 1 ? ' result-view__cards--multi' : ''}${
          dense ? ' result-view__cards--dense' : ''
        }`}
      >
        {items.map((item, index) => (
          <SignatureCard
            key={index}
            item={item}
            collapsible={items.length > 1}
            dense={dense}
            expanded={dense ? expandedIndices.has(index) : undefined}
            onToggle={dense ? () => toggleOne(index) : undefined}
          />
        ))}
      </div>

      <div className="result-view__actions">
        <DownloadReportButton result={result} />
        <button type="button" className="btn btn--ghost" onClick={onReset}>
          <IconRotate size={16} />
          Verify another document
        </button>
      </div>
    </section>
  )
}
