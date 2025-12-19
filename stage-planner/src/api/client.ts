import { useAuth } from '../auth/auth'
import { logAppError } from '../app/errorLog'

export const API_BASE =
  import.meta.env.VITE_API_BASE || (import.meta.env.PROD ? '/api' : 'http://localhost:3001')

type ApiStatus = {
  inFlight: number
  lastSuccessAt: number | null
  lastErrorAt: number | null
}

const status: ApiStatus = { inFlight: 0, lastSuccessAt: null, lastErrorAt: null }
const listeners = new Set<(s: ApiStatus) => void>()

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
        errName: (e as any)?.name,
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


