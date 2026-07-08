import { useState } from 'react'
import { IconLock } from '../icons.jsx'
import ErrorNotice from './ErrorNotice.jsx'

export default function PasswordPrompt({ fileName, error, onSubmit, onCancel }) {
  const [password, setPassword] = useState('')

  function handleSubmit(event) {
    event.preventDefault()
    if (password) onSubmit(password)
  }

  return (
    <section className="password-prompt">
      <div className="password-prompt__icon">
        <IconLock size={28} />
      </div>
      <h2>This PDF is password-protected</h2>
      <p className="password-prompt__file">{fileName}</p>

      <form onSubmit={handleSubmit}>
        <label htmlFor="pdf-password" className="visually-hidden">
          PDF password
        </label>
        <input
          id="pdf-password"
          type="password"
          autoFocus
          placeholder="Enter the document password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {error && <ErrorNotice code="incorrect_password" message={error} />}
        <div className="password-prompt__actions">
          <button type="submit" className="btn btn--primary" disabled={!password}>
            Unlock &amp; verify
          </button>
          <button type="button" className="btn btn--ghost" onClick={onCancel}>
            Choose a different file
          </button>
        </div>
      </form>

      <p className="password-prompt__reassurance">
        Your password is used only for this check — it's never stored or logged.
      </p>
    </section>
  )
}
