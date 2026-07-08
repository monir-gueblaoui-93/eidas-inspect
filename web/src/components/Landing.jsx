import UploadZone from './UploadZone.jsx'
import ErrorNotice from './ErrorNotice.jsx'
import { IconShieldCheck } from '../icons.jsx'

export default function Landing({ onFileSelected, error }) {
  return (
    <section className="landing">
      <h1 className="landing__headline">
        Check if your signed document is <em>genuinely</em> valid.
      </h1>
      <p className="landing__subhead">
        Upload a signed or sealed PDF and get a plain-language verdict on whether it's
        real, intact, and qualified under EU eIDAS rules — no jargon, no account.
      </p>

      <UploadZone onFileSelected={onFileSelected} />
      {error && <ErrorNotice code={error.code} message={error.message} />}

      <p className="landing__trust">
        <IconShieldCheck size={18} />
        Your document is processed in memory and never stored.
      </p>
    </section>
  )
}
