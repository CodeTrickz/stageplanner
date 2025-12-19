import { Alert, Box, Button, Paper, Stack, Typography } from '@mui/material'
import { useEffect, useState } from 'react'
import { Link as RouterLink, useSearchParams } from 'react-router-dom'
import { API_BASE } from '../api/client'

const API = API_BASE

// StrictMode in dev can mount/unmount/remount components, causing double calls.
// We track per-token requests/results at module scope so each token is verified only once.
const tokenPromise = new Map<string, Promise<void>>()
const tokenResult = new Map<string, { ok: boolean; error?: string }>()

function verifyOnce(token: string) {
  const existing = tokenPromise.get(token)
  if (existing) return existing

  const p = (async () => {
    const controller = new AbortController()
    const t = setTimeout(() => controller.abort(), 12000)
    try {
      const res = await fetch(`${API}/auth/verify?token=${encodeURIComponent(token)}`, {
        signal: controller.signal,
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data?.error || 'verify_failed')
      tokenResult.set(token, { ok: true })
    } catch (e) {
      const msg =
        e instanceof Error
          ? e.name === 'AbortError'
            ? 'timeout'
            : e.message
          : 'verify_failed'
      tokenResult.set(token, { ok: false, error: msg })
    } finally {
      clearTimeout(t)
    }
  })()

  tokenPromise.set(token, p)
  return p
}

export function VerifyPage() {
  const [params] = useSearchParams()
  const token = params.get('token') || ''
  const [state, setState] = useState<'idle' | 'ok' | 'error'>('idle')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    async function run() {
      if (!token) {
        setState('error')
        setError('missing_token')
        return
      }
      try {
        await verifyOnce(token)
        const r = tokenResult.get(token)
        if (!r) throw new Error('verify_failed')
        if (!r.ok) throw new Error(r.error || 'verify_failed')
        if (!cancelled) setState('ok')
      } catch (e) {
        if (!cancelled) {
          setState('error')
          const msg = e instanceof Error ? e.message : 'verify_failed'
          if (msg === 'timeout') {
            setError(
              `Timeout: geen antwoord van de backend. Check of je backend bereikbaar is via ${API_BASE} (in Docker: open de app via http://localhost:8080).`,
            )
          } else if (msg === 'invalid_or_expired_token') {
            setError(
              'Deze activatie-link is ongeldig of al gebruikt. Probeer in te loggen. Als dat niet lukt: vraag een nieuwe verificatie aan (of laat een admin je account verifiëren).',
            )
          } else {
            setError(msg)
          }
        }
      }
    }
    void run()
    return () => {
      cancelled = true
    }
  }, [token])

  return (
    <Box sx={{ display: 'grid', placeItems: 'center', minHeight: '60vh' }}>
      <Paper sx={{ p: 3, width: 'min(560px, 100%)' }}>
        <Stack spacing={2}>
          <Typography variant="h5" sx={{ fontWeight: 900 }}>
            Account activeren
          </Typography>

          {state === 'idle' && <Alert severity="info">Activeren…</Alert>}
          {state === 'ok' && (
            <Alert severity="success">
              Gelukt! Je account is geactiveerd. Je kan nu inloggen.
            </Alert>
          )}
          {state === 'error' && <Alert severity="error">{error ?? 'verify_failed'}</Alert>}

          <Stack direction="row" spacing={1} justifyContent="flex-end">
            <Button variant="contained" component={RouterLink} to="/login">
              Naar login
            </Button>
          </Stack>
        </Stack>
      </Paper>
    </Box>
  )
}


