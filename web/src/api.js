/**
 * Thin client for the eidas-inspect API. Every error the API can return
 * arrives as `{"error": {"code": "...", "message": "..."}}` — this wraps
 * that into a typed ApiError so components can branch on `.code` instead
 * of parsing prose.
 */

export class ApiError extends Error {
  constructor(code, message, status) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.status = status
  }
}

async function errorFromResponse(response) {
  let code = 'unknown_error'
  let message = 'Something went wrong. Please try again.'
  try {
    const data = await response.json()
    if (data && data.error) {
      code = data.error.code ?? code
      message = data.error.message ?? message
    }
  } catch {
    // Non-JSON error body (e.g. a proxy/edge failure) — fall back to defaults.
  }
  return new ApiError(code, message, response.status)
}

export async function verifyDocument(file, password) {
  const form = new FormData()
  form.append('file', file)
  if (password) form.append('password', password)

  let response
  try {
    response = await fetch('/api/verify', { method: 'POST', body: form })
  } catch {
    throw new ApiError('network_error', "Couldn't reach the server. Check your connection and try again.")
  }
  if (!response.ok) throw await errorFromResponse(response)
  return response.json()
}

export async function requestReport(result) {
  let response
  try {
    response = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(result),
    })
  } catch {
    throw new ApiError('network_error', "Couldn't reach the server. Check your connection and try again.")
  }
  if (!response.ok) throw await errorFromResponse(response)
  return response.blob()
}
