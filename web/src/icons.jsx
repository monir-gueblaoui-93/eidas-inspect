/**
 * Hand-rolled stroke icons — small, dependency-free, `currentColor`-based so
 * they inherit text color and always ship an accessible label alongside
 * (icons never carry meaning through color alone).
 */

const base = {
  width: 24,
  height: 24,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
}

function Svg({ size = 24, children, ...rest }) {
  return (
    <svg {...base} width={size} height={size} aria-hidden="true" focusable="false" {...rest}>
      {children}
    </svg>
  )
}

export function IconUpload(props) {
  return (
    <Svg {...props}>
      <path d="M12 16V4" />
      <path d="M7 9l5-5 5 5" />
      <path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" />
    </Svg>
  )
}

export function IconLock(props) {
  return (
    <Svg {...props}>
      <rect x="5" y="11" width="14" height="9" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </Svg>
  )
}

export function IconShieldCheck(props) {
  return (
    <Svg {...props}>
      <path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z" />
      <path d="M9 12l2 2 4-4" />
    </Svg>
  )
}

export function IconPerson(props) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="8" r="3.3" />
      <path d="M5 20c0-3.9 3.1-6.5 7-6.5s7 2.6 7 6.5" />
    </Svg>
  )
}

export function IconBuilding(props) {
  return (
    <Svg {...props}>
      <rect x="4" y="3" width="12" height="18" rx="1" />
      <path d="M9 8h2M9 12h2M9 16h2" />
      <path d="M16 10h4v11h-4" />
    </Svg>
  )
}

export function IconClock(props) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </Svg>
  )
}

export function IconCheckCircle(props) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M8.3 12.3l2.5 2.5 5-5" />
    </Svg>
  )
}

export function IconAlertTriangle(props) {
  return (
    <Svg {...props}>
      <path d="M12 4.5l9 15.5H3z" />
      <path d="M12 10v4" />
      <circle cx="12" cy="17.3" r="0.15" fill="currentColor" stroke="none" />
    </Svg>
  )
}

export function IconXCircle(props) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M9 9l6 6M15 9l-6 6" />
    </Svg>
  )
}

export function IconInfoCircle(props) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5" />
      <circle cx="12" cy="8" r="0.15" fill="currentColor" stroke="none" />
    </Svg>
  )
}

export function IconChevronDown(props) {
  return (
    <Svg {...props}>
      <path d="M6 9l6 6 6-6" />
    </Svg>
  )
}

export function IconDownload(props) {
  return (
    <Svg {...props}>
      <path d="M12 4v11" />
      <path d="M7 11l5 5 5-5" />
      <path d="M4 19h16" />
    </Svg>
  )
}

export function IconFileSearch(props) {
  return (
    <Svg {...props}>
      <path d="M7 3h7l4 4v13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" />
      <path d="M14 3v4h4" />
      <circle cx="11" cy="14" r="2.3" />
      <path d="M12.8 15.8L15 18" />
    </Svg>
  )
}

export function IconRotate(props) {
  return (
    <Svg {...props}>
      <path d="M4 12a8 8 0 0 1 14-5.3M20 12a8 8 0 0 1-14 5.3" />
      <path d="M18 3v4h-4M6 21v-4h4" />
    </Svg>
  )
}
