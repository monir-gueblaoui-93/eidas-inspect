import { useEffect, useRef, useState } from 'react'
import { IconFileSearch, IconPerson, IconShieldCheck, IconBuilding, IconClock, IconCheckCircle } from '../icons.jsx'

const STAGES = [
  { label: 'Reading document', icon: IconFileSearch },
  { label: 'Finding signatures', icon: IconPerson },
  { label: 'Checking integrity', icon: IconShieldCheck },
  { label: 'Consulting EU Trusted Lists', icon: IconBuilding },
  { label: 'Checking revocation status', icon: IconClock },
]

const NORMAL_STEP_MS = 1100
const FAST_STEP_MS = 220
const FLOURISH_MS = 550

/**
 * The API call is synchronous and returns no real progress — this paces a
 * step sequence client-side instead. Normal pacing while the request is
 * still in flight; if it settles before the sequence finishes, this fast-
 * forwards through the remaining stages rather than cutting the story
 * short, then plays a short "all done" flourish before calling onFinished.
 *
 * `isComplete` is read via a ref inside the timer loop (not as an effect
 * dependency) so the sequence keeps going from wherever it is — flipping
 * to "fast" pacing — instead of restarting from step 0 the moment the API
 * settles.
 */
export default function VerifyingAnimation({ isComplete, onFinished }) {
  const [stepIndex, setStepIndex] = useState(0)
  const [done, setDone] = useState(false)
  const isCompleteRef = useRef(isComplete)
  isCompleteRef.current = isComplete
  const onFinishedRef = useRef(onFinished)
  onFinishedRef.current = onFinished

  useEffect(() => {
    let cancelled = false
    let timer

    function tick(index) {
      if (cancelled) return
      if (index >= STAGES.length - 1) {
        setStepIndex(STAGES.length - 1)
        if (isCompleteRef.current) {
          setDone(true)
          timer = setTimeout(() => {
            if (!cancelled) onFinishedRef.current()
          }, FLOURISH_MS)
        } else {
          // Sequence has run its course but the API is still in flight —
          // hold on the last stage, pulsing, and re-check shortly.
          timer = setTimeout(() => tick(index), FAST_STEP_MS)
        }
        return
      }
      setStepIndex(index)
      const delay = isCompleteRef.current ? FAST_STEP_MS : NORMAL_STEP_MS
      timer = setTimeout(() => tick(index + 1), delay)
    }

    tick(0)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [])

  return (
    <section className="verifying" aria-live="polite">
      <h2 className="verifying__title">
        {done ? 'All checks complete' : 'Verifying your document…'}
      </h2>
      <ol className="verifying__steps">
        {STAGES.map((stage, index) => {
          const state = done || index < stepIndex ? 'done' : index === stepIndex ? 'active' : 'pending'
          const Icon = state === 'done' ? IconCheckCircle : stage.icon
          return (
            <li key={stage.label} className={`verifying__step verifying__step--${state}`}>
              <span className="verifying__badge">
                <Icon size={20} />
              </span>
              <span className="verifying__label">{stage.label}</span>
            </li>
          )
        })}
      </ol>
    </section>
  )
}
