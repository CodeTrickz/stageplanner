import { Alert, Box, Button, Paper, Stack, TextField, Typography } from '@mui/material'
import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { API_BASE } from '../api/client'
import { useAuth } from '../auth/auth'
import { useSettings } from '../app/settings'

const API = API_BASE

export function LoginPage() {
  const { login } = useAuth()
  const { startPage } = useSettings()
  const nav = useNavigate()
  const [params] = useSearchParams()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [password, setPassword] = useState('')
  const [passwordConfirm, setPasswordConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [validationIssues, setValidationIssues] = useState<Array<{ path: string; message: string }>>([])
  const [info, setInfo] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit() {
    setError(null)
    setInfo(null)
    setValidationIssues([])
    setBusy(true)
    try {
      if (mode === 'register' && password !== passwordConfirm) {
        throw new Error('password_mismatch')
      }
      const res = await fetch(`${API}/auth/${mode}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body:
          mode === 'login'
            ? JSON.stringify({ email, password })
            : JSON.stringify({ email, username, firstName, lastName, password, passwordConfirm }),
      })
      const data = await res.json()
      if (!res.ok) {
        // Show validation issues if available
        if (data?.issues && Array.isArray(data.issues)) {
          setValidationIssues(data.issues)
        }
        throw new Error(data?.error || 'request_failed')
      }

      // register: verification required
      if (mode === 'register') {
        setInfo(
          'Account aangemaakt. Check je e-mail om te activeren. (Dev: kijk in backend/data/mails.log. Docker: `docker compose exec backend cat /app/data/mails.log`.)',
        )
        setMode('login')
        return
      }

      login(data.token, data.user)
      const next = params.get('next')
      nav(next ? decodeURIComponent(next) : (startPage || '/dashboard'), { replace: true })
    } catch (e) {
      setError(e instanceof Error ? e.message : 'login_failed')
      // Clear validation issues if it's not an invalid_input error
      if (e instanceof Error && e.message !== 'invalid_input') {
        setValidationIssues([])
      }
    } finally {
      setBusy(false)
    }
  }

  async function resendVerification() {
    setError(null)
    setInfo(null)
    setBusy(true)
    try {
      const res = await fetch(`${API}/auth/resend-verify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data?.error || 'resend_failed')
      setInfo('Nieuwe activatie-link verstuurd. (Dev: backend/data/mails.log. Docker: `docker compose exec backend cat /app/data/mails.log`)')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'resend_failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Box sx={{ display: 'grid', placeItems: 'center', minHeight: '60vh', px: { xs: 1, sm: 2 } }}>
      <Paper sx={{ p: { xs: 2, sm: 3 }, width: '100%', maxWidth: { xs: '100%', sm: 520 } }}>
        <Stack spacing={{ xs: 1.5, sm: 2 }}>
          <Typography variant="h5" sx={{ fontWeight: 900, fontSize: { xs: '1.125rem', sm: '1.25rem' } }}>
            {mode === 'login' ? 'Inloggen' : 'Account maken'}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Backend: <b>{API}</b>
          </Typography>

          <TextField label="Email" value={email} onChange={(e) => setEmail(e.target.value)} />

          {mode === 'register' && (
            <>
              <TextField label="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
              <Stack direction="column" spacing={{ xs: 1.5, sm: 2 }} sx={{ '@media (min-width:600px)': { flexDirection: 'row' } }}>
                <TextField label="Voornaam" value={firstName} onChange={(e) => setFirstName(e.target.value)} fullWidth />
                <TextField label="Achternaam" value={lastName} onChange={(e) => setLastName(e.target.value)} fullWidth />
              </Stack>
            </>
          )}

          <TextField
            label="Wachtwoord"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {mode === 'register' && (
            <TextField
              label="Herhaal wachtwoord"
              type="password"
              value={passwordConfirm}
              onChange={(e) => setPasswordConfirm(e.target.value)}
            />
          )}

          {info && <Alert severity="success">{info}</Alert>}
          {error && (
            <Alert severity="error">
              {error}
              {validationIssues.length > 0 && (
                <Box component="ul" sx={{ mt: 1, mb: 0, pl: 2 }}>
                  {validationIssues.map((issue, idx) => (
                    <li key={idx}>
                      <strong>{issue.path}:</strong> {issue.message}
                    </li>
                  ))}
                </Box>
              )}
            </Alert>
          )}
          {error === 'email_not_verified' && (
            <Alert severity="info">
              Je email is nog niet geactiveerd.{' '}
              <Button variant="text" onClick={() => void resendVerification()} disabled={busy || !email}>
                Stuur verificatie opnieuw
              </Button>
            </Alert>
          )}

          <Stack direction="row" spacing={1} justifyContent="flex-end">
            <Button
              variant="text"
              onClick={() => setMode((m) => (m === 'login' ? 'register' : 'login'))}
              disabled={busy}
            >
              {mode === 'login' ? 'Account maken' : 'Ik heb al een account'}
            </Button>
            <Button
              variant="contained"
              onClick={() => void submit()}
              disabled={
                busy ||
                !email ||
                !password ||
                (mode === 'register' && (!username || !firstName || !lastName || !passwordConfirm))
              }
            >
              {mode === 'login' ? 'Login' : 'Register'}
            </Button>
          </Stack>
        </Stack>
      </Paper>
    </Box>
  )
}


