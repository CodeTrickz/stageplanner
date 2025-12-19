import { useEffect, useState } from 'react'
import { API_BASE } from '../api/client'
import { logAppError } from '../app/errorLog'

export function useBackendHealth(enabled: boolean) {
  const [ok, setOk] = useState<boolean | null>(null)

  useEffect(() => {
    if (!enabled) {
      setOk(null)
      return
    }
    let cancelled = false
    async function ping() {
      try {
        const ctrl = new AbortController()
        const t = setTimeout(() => ctrl.abort(), 3500)
        const res = await fetch(`${API_BASE}/health`, { signal: ctrl.signal })
        clearTimeout(t)
        const data = await res.json().catch(() => ({}))
        if (!cancelled) setOk(!!data?.ok)
      } catch (e) {
        if (!cancelled) setOk(false)
        const errName = (e as any)?.name
        const errMsg = e instanceof Error ? e.message : String(e)
        void logAppError({
          level: 'warn',
          source: 'api',
          message: 'backend_health_failed',
          meta: { apiBase: API_BASE, errName, errMsg, err: String(e) },
        })
      }
    }
    void ping()
    const t = setInterval(ping, 15000)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [enabled])

  return ok
}



