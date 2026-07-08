import { IconAlertTriangle, IconClock } from '../icons.jsx'

/** Friendly, non-alarming notice for upload rejections and rate limiting —
 * per PRD these are "friendly rejections," not scary failure states. */
export default function ErrorNotice({ code, message }) {
  const Icon = code === 'rate_limited' ? IconClock : IconAlertTriangle
  return (
    <div className="notice" role="alert">
      <Icon size={20} />
      <span>{message}</span>
    </div>
  )
}
