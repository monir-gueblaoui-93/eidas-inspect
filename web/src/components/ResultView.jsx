import VerdictBanner from './VerdictBanner.jsx'
import SignatureCard from './SignatureCard.jsx'
import UnsignedState from './UnsignedState.jsx'
import DownloadReportButton from './DownloadReportButton.jsx'
import { IconRotate } from '../icons.jsx'

export default function ResultView({ result, onReset }) {
  if (result.verdict === 'no-signatures') {
    return <UnsignedState onReset={onReset} />
  }

  return (
    <section className="result-view">
      <VerdictBanner
        verdict={result.verdict}
        plainSummary={result.plain_summary}
        breakdown={result.verdict_breakdown}
      />

      <div className={`result-view__cards${result.items.length > 1 ? ' result-view__cards--multi' : ''}`}>
        {result.items.map((item, index) => (
          <SignatureCard key={index} item={item} collapsible={result.items.length > 1} />
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
