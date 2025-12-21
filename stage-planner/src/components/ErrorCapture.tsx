import { useEffect } from 'react'
import { logAppError } from '../app/errorLog'

export function ErrorCapture() {
  useEffect(() => {
    function onError(ev: ErrorEvent) {
      void logAppError({
        level: 'error',
        source: 'window',
        message: ev.message || 'window.error',
        stack: ev.error instanceof Error ? ev.error.stack : undefined,
        meta: { filename: ev.filename, lineno: ev.lineno, colno: ev.colno },
      })
    }

    function onUnhandledRejection(ev: PromiseRejectionEvent) {
      const reason = ev.reason
      const message = reason instanceof Error ? reason.message : typeof reason === 'string' ? reason : 'unhandledrejection'
      const stack = reason instanceof Error ? reason.stack : undefined
      void logAppError({
        level: 'error',
        source: 'unhandledrejection',
        message,
        stack,
        meta: { reason },
      })
    }

    window.addEventListener('error', onError)
    window.addEventListener('unhandledrejection', onUnhandledRejection)
    return () => {
      window.removeEventListener('error', onError)
      window.removeEventListener('unhandledrejection', onUnhandledRejection)
    }
  }, [])

  return null
}









