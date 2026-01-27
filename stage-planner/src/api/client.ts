import { useAuth } from '../auth/auth'
import { logAppError } from '../app/errorLog'

export const API_BASE =
  import.meta.env.VITE_API_BASE || (import.meta.env.PROD ? '/api' : 'http://localhost:3001')

type ApiStatus = {
  inFlight: number
  lastSuccessAt: number | null
  lastErrorAt: number | null
}

export type RateLimitEvent = {
  retryAfterSec: number
  message: string
}

const status: ApiStatus = { inFlight: 0, lastSuccessAt: null, lastErrorAt: null }
const listeners = new Set<(s: ApiStatus) => void>()
const rateLimitListeners = new Set<(evt: RateLimitEvent) => void>()

function emit() {
  const snapshot = { ...status }
  for (const l of listeners) l(snapshot)
}

export function subscribeApiStatus(fn: (s: ApiStatus) => void) {
  listeners.add(fn)
  fn({ ...status })
  return () => {
    listeners.delete(fn)
  }
}

export function subscribeRateLimit(fn: (evt: RateLimitEvent) => void) {
  rateLimitListeners.add(fn)
  return () => {
    rateLimitListeners.delete(fn)
  }
}

function emitRateLimit(evt: RateLimitEvent) {
  for (const l of rateLimitListeners) l(evt)
}

export async function apiFetch(path: string, options: RequestInit & { token?: string } = {}) {
  status.inFlight += 1
  emit()
  try {
    const url = `${API_BASE}${path}`
    const method = (options.method || 'GET').toUpperCase()
    const res = await fetch(url, {
      ...options,
      headers: {
        ...(options.headers || {}),
        ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      },
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) {
      if (res.status === 429) {
        const retryAfterHeader = Number(res.headers.get('retry-after'))
        const retryAfterSec = Number.isFinite(retryAfterHeader)
          ? retryAfterHeader
          : Number.isFinite(Number(data?.retryAfter))
            ? Number(data?.retryAfter)
            : 1
        const message = `Te veel verzoeken. Probeer opnieuw over ${retryAfterSec} seconden.`
        emitRateLimit({ retryAfterSec, message })
        status.lastErrorAt = Date.now()
        emit()
        return null
      }
      status.lastErrorAt = Date.now()
      emit()
      void logAppError({
        level: 'error',
        source: 'api',
        message: data?.error || `http_${res.status}`,
        meta: { url, path, method, status: res.status, statusText: res.statusText, data },
      })
      throw new Error(data?.error || 'api_error')
    }
    status.lastSuccessAt = Date.now()
    emit()
    return data
  } catch (e) {
    status.lastErrorAt = Date.now()
    emit()
    void logAppError({
      level: 'error',
      source: 'api',
      message: e instanceof Error ? e.message : 'api_error',
      meta: {
        url: `${API_BASE}${path}`,
        path,
        method: (options.method || 'GET').toUpperCase(),
        errName: e instanceof Error ? e.name : undefined,
        errMessage: e instanceof Error ? e.message : String(e),
      },
    })
    throw e
  } finally {
    status.inFlight = Math.max(0, status.inFlight - 1)
    emit()
  }
}

// convenience hook
export function useApiToken() {
  const { token } = useAuth()
  return token
}


