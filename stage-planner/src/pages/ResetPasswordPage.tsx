import { Alert, Box, Button, Paper, Stack, TextField, Typography } from '@mui/material'
import { useState } from 'react'
import { Link as RouterLink, useSearchParams } from 'react-router-dom'
import { API_BASE } from '../api/client'

const API = API_BASE

export function ResetPasswordPage() {
  const [params] = useSearchParams()
  const token = params.get('token') || ''
  const [password, setPassword] = useState('')
  const [passwordConfirm, setPasswordConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [info, setInfo] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function submit() {
    setError(null)
    setInfo(null)
    if (!token) {
      setError('missing_token')
      return
    }
    setBusy(true)
    try {
      const res = await fetch(`${API}/auth/reset-password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token, password, passwordConfirm }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data?.error || 'reset_failed')
      setInfo('Wachtwoord gewijzigd. Je kan nu inloggen.')
      setPassword('')
      setPasswordConfirm('')
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'reset_failed'
      if (msg === 'invalid_or_expired_token') {
        setError('Deze reset-link is ongeldig of verlopen. Vraag een nieuwe link aan.')
      } else if (msg === 'password_mismatch') {
        setError('Wachtwoorden komen niet overeen.')
      } else if (msg === 'weak_password') {
        setError('Wachtwoord te zwak (min 10 tekens, letters en cijfers, geen spaties).')
      } else {
        setError(msg)
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <Box sx={{ display: 'grid', placeItems: 'center', minHeight: '60vh', px: 2 }}>
      <Paper sx={{ p: { xs: 2.5, sm: 3 }, width: 'min(520px, 100%)' }}>
        <Stack spacing={2}>
          <Typography variant="h5" sx={{ fontWeight: 900 }}>
            Wachtwoord resetten
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Kies een nieuw wachtwoord. Het moet minimaal 10 tekens bevatten, met letters en cijfers.
          </Typography>

          <TextField
            label="Nieuw wachtwoord"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            fullWidth
          />
          <TextField
            label="Herhaal nieuw wachtwoord"
            type="password"
            value={passwordConfirm}
            onChange={(e) => setPasswordConfirm(e.target.value)}
            autoComplete="new-password"
            fullWidth
          />

          {info && <Alert severity="success">{info}</Alert>}
          {error && <Alert severity="error">{error}</Alert>}

          <Stack direction="row" spacing={1} justifyContent="flex-end">
            <Button component={RouterLink} to="/login" variant="text">
              Naar login
            </Button>
            <Button
              variant="contained"
              onClick={() => void submit()}
              disabled={busy || !password || !passwordConfirm}
            >
              Reset
            </Button>
          </Stack>
        </Stack>
      </Paper>
    </Box>
  )
}
