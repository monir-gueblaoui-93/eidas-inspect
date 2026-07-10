import { useRef, useState } from 'react'
import Landing from './components/Landing.jsx'
import PasswordPrompt from './components/PasswordPrompt.jsx'
import VerifyingAnimation from './components/VerifyingAnimation.jsx'
import ResultView from './components/ResultView.jsx'
import Footer from './components/Footer.jsx'
import { verifyDocument } from './api.js'

const MAX_BYTES = 50 * 1024 * 1024

function precheckFile(file) {
  const looksLikePdf = file.type === 'application/pdf' || file.name?.toLowerCase().endsWith('.pdf')
  if (!looksLikePdf) {
    return { code: 'not_a_pdf', message: 'PDF only for now — other formats are coming soon.' }
  }
  if (file.size > MAX_BYTES) {
    return { code: 'file_too_large', message: 'Files over 50 MB are not supported.' }
  }
  return null
}

export default function App() {
  const [phase, setPhase] = useState('landing') // landing | password | verifying | result
  const [file, setFile] = useState(null)
  const [uploadError, setUploadError] = useState(null)
  const [passwordError, setPasswordError] = useState(null)
  const [result, setResult] = useState(null)
  const [apiSettled, setApiSettled] = useState(false)
  const outcomeRef = useRef(null)

  function beginVerification(selectedFile, password) {
    setFile(selectedFile)
    setUploadError(null)
    setPasswordError(null)
    setApiSettled(false)
    outcomeRef.current = null
    setPhase('verifying')

    verifyDocument(selectedFile, password)
      .then((data) => {
        outcomeRef.current = { type: 'success', data }
      })
      .catch((err) => {
        outcomeRef.current = { type: 'error', err }
      })
      .finally(() => setApiSettled(true))
  }

  function handleFileSelected(selectedFile) {
    const problem = precheckFile(selectedFile)
    if (problem) {
      setUploadError(problem)
      return
    }
    beginVerification(selectedFile, null)
  }

  function handlePasswordSubmit(password) {
    beginVerification(file, password)
  }

  function handleReset() {
    setPhase('landing')
    setFile(null)
    setResult(null)
    setUploadError(null)
    setPasswordError(null)
  }

  function handleAnimationFinished() {
    const outcome = outcomeRef.current
    if (!outcome) return

    if (outcome.type === 'success') {
      setResult(outcome.data)
      setPhase('result')
      return
    }

    const { err } = outcome
    if (err.code === 'password_required') {
      setPhase('password')
    } else if (err.code === 'incorrect_password') {
      setPasswordError(err.message)
      setPhase('password')
    } else {
      setUploadError({ code: err.code, message: err.message })
      setPhase('landing')
    }
  }

  const isWideResult = phase === 'result' && result?.items?.length > 1

  return (
    <div className="app-shell">
      <main className={`app-main${isWideResult ? ' app-main--wide' : ''}`}>
        {phase === 'landing' && <Landing onFileSelected={handleFileSelected} error={uploadError} />}
        {phase === 'password' && (
          <PasswordPrompt
            fileName={file?.name}
            error={passwordError}
            onSubmit={handlePasswordSubmit}
            onCancel={handleReset}
          />
        )}
        {phase === 'verifying' && (
          <VerifyingAnimation isComplete={apiSettled} onFinished={handleAnimationFinished} />
        )}
        {phase === 'result' && result && <ResultView result={result} onReset={handleReset} />}
      </main>
      <Footer />
    </div>
  )
}
