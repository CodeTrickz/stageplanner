import { Alert, Box, Button, Paper, Stack, Typography } from '@mui/material'
import { useEffect, useState } from 'react'
import { Link as RouterLink, useNavigate, useSearchParams } from 'react-router-dom'
import { API_BASE } from '../api/client'
import { useAuth } from '../auth/auth'
import { useWorkspace } from '../hooks/useWorkspace'

const API = API_BASE

// Track per-token requests/results to prevent double processing
const tokenPromise = new Map<string, Promise<{ ok: boolean; error?: string; workspaceId?: string }>>()
const tokenResult = new Map<string, { ok: boolean; error?: string; workspaceId?: string }>()

function acceptOnce(token: string, userToken: string | null) {
  const existing = tokenPromise.get(token)
  if (existing) return existing

  const p = (async () => {
    const controller = new AbortController()
    const t = setTimeout(() => controller.abort(), 12000)
    try {
      if (!userToken) {
        throw new Error('Je moet eerst inloggen om de uitnodiging te accepteren')
      }

      // Debug: log the request details
      console.log('Sending accept request:', { 
        url: `${API}/workspaces/accept`,
        hasToken: !!userToken,
        tokenLength: userToken?.length,
        tokenPrefix: userToken?.substring(0, 20) + '...'
      })
      
      const res = await fetch(`${API}/workspaces/accept`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({ token }),
        signal: controller.signal,
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        const errorMsg = data?.error || `accept_failed (${res.status})`
        // Log the full error for debugging
        console.error('Accept invitation error:', { status: res.status, data, token: token.substring(0, 10) + '...' })
        throw new Error(errorMsg)
      }
      const result = { ok: true, workspaceId: data.workspaceId }
      tokenResult.set(token, result)
      return result
    } catch (e) {
      const msg =
        e instanceof Error
          ? e.name === 'AbortError'
            ? 'timeout'
            : e.message
          : 'accept_failed'
      const result = { ok: false, error: msg }
      tokenResult.set(token, result)
      return result
    } finally {
      clearTimeout(t)
    }
  })()

  tokenPromise.set(token, p)
  return p
}

export function AcceptInvitePage() {
  const [params] = useSearchParams()
  const token = params.get('token')
  const { token: userToken, user } = useAuth()
  const { refreshWorkspaces } = useWorkspace()
  const nav = useNavigate()
  const [result, setResult] = useState<{ ok: boolean; error?: string; workspaceId?: string } | null>(null)
  const [loading, setLoading] = useState(true)
  
  // Debug: log auth state
  useEffect(() => {
    console.log('AcceptInvitePage auth state:', { hasToken: !!userToken, hasUser: !!user, userEmail: user?.email })
  }, [userToken, user])

  useEffect(() => {
    if (!token) {
      setResult({ ok: false, error: 'Geen token gevonden in de link' })
      setLoading(false)
      return
    }

    const existing = tokenResult.get(token)
    if (existing) {
      setResult(existing)
      setLoading(false)
      return
    }

    // Wait for auth state to be ready before attempting acceptance
    // The useEffect will re-run when userToken becomes available (it's in the dependency array)
    if (!userToken) {
      // Token not yet available, wait for it to load
      // Don't set error yet - the effect will re-run when token becomes available
      return
    }

    // Token is available, proceed with acceptance
    void acceptOnce(token, userToken).then((res) => {
      setResult(res)
      setLoading(false)
      if (res.ok && 'workspaceId' in res && res.workspaceId) {
        // Refresh workspaces to include the new one
        void refreshWorkspaces()
        // Navigate to team page after a short delay
        setTimeout(() => {
          nav('/team')
        }, 2000)
      }
    })
  }, [token, userToken, nav, refreshWorkspaces])

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <Paper sx={{ p: 4, maxWidth: 500, width: '100%', m: 2 }}>
          <Stack spacing={2} alignItems="center">
            <Typography variant="h5">Uitnodiging verwerken...</Typography>
            <Typography variant="body2" color="text.secondary">
              Even geduld...
            </Typography>
          </Stack>
        </Paper>
      </Box>
    )
  }

  if (!result) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <Paper sx={{ p: 4, maxWidth: 500, width: '100%', m: 2 }}>
          <Alert severity="error">Onbekende fout</Alert>
        </Paper>
      </Box>
    )
  }

  if (result.ok) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <Paper sx={{ p: 4, maxWidth: 500, width: '100%', m: 2 }}>
          <Stack spacing={2}>
            <Alert severity="success">Uitnodiging geaccepteerd!</Alert>
            <Typography variant="body1">
              Je bent nu lid van de workspace. Je wordt doorgestuurd naar de Team pagina...
            </Typography>
            <Button component={RouterLink} to="/team" variant="contained" fullWidth>
              Naar Team pagina
            </Button>
          </Stack>
        </Paper>
      </Box>
    )
  }

  const errorMessage =
    result.error === 'unauthorized' || result.error === 'Je moet eerst inloggen om de uitnodiging te accepteren'
      ? 'Je moet eerst inloggen om de uitnodiging te accepteren.'
      : result.error === 'email_mismatch'
        ? 'Het e-mailadres van je account komt niet overeen met het uitgenodigde e-mailadres.'
        : result.error === 'token_expired'
          ? 'Deze uitnodiging is verlopen. Vraag een nieuwe uitnodiging aan.'
          : result.error === 'already_accepted'
            ? 'Deze uitnodiging is al geaccepteerd.'
            : result.error === 'invalid_token'
              ? 'Ongeldige uitnodigingslink.'
              : result.error === 'accept_failed'
                ? 'Er is een fout opgetreden bij het accepteren van de uitnodiging. Probeer het opnieuw.'
                : `Er is een fout opgetreden: ${result.error}`

  return (
    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
      <Paper sx={{ p: 4, maxWidth: 500, width: '100%', m: 2 }}>
        <Stack spacing={2}>
          <Alert severity="error">{errorMessage}</Alert>
          {(result.error === 'unauthorized' || result.error === 'Je moet eerst inloggen om de uitnodiging te accepteren') && (
            <Button component={RouterLink} to={`/login?next=${encodeURIComponent(`/workspace/accept?token=${token || ''}`)}`} variant="contained" fullWidth>
              Inloggen
            </Button>
          )}
          {result.error === 'email_mismatch' && (
            <Typography variant="body2" color="text.secondary">
              Log in met het account dat overeenkomt met het uitgenodigde e-mailadres.
            </Typography>
          )}
          <Button component={RouterLink} to="/" variant="outlined" fullWidth>
            Terug naar startpagina
          </Button>
        </Stack>
      </Paper>
    </Box>
  )
}

