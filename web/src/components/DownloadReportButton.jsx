import { useState } from 'react'
import { IconDownload } from '../icons.jsx'
import { requestReport } from '../api.js'

export default function DownloadReportButton({ result }) {
  const [status, setStatus] = useState('idle') // idle | loading | error

  async function handleClick() {
    setStatus('loading')
    try {
      const blob = await requestReport(result)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = 'eidas-inspect-report.pdf'
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
      setStatus('idle')
    } catch {
      setStatus('error')
    }
  }

  return (
    <div className="download-report">
      <button type="button" className="btn btn--secondary" onClick={handleClick} disabled={status === 'loading'}>
        <IconDownload size={18} />
        {status === 'loading' ? 'Preparing report…' : 'Download report'}
      </button>
      {status === 'error' && (
        <p className="download-report__error">
          Couldn't generate the report just now — please try again.
        </p>
      )}
    </div>
  )
}
