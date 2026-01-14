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
  const [forgotMode, setForgotMode] = useState(false)

  async function submit() {
    setError(null)
    setInfo(null)
    setValidationIssues([])
    setForgotMode(false)
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
            ? JSON.stringify({ identifier: email, password })
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

  const isLogin = mode === 'login'

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        px: { xs: 2, sm: 3 },
        py: { xs: 4, sm: 6 },
        background:
          'radial-gradient(circle at top left, rgba(25,118,210,0.18), transparent 55%), radial-gradient(circle at bottom right, rgba(156,39,176,0.16), transparent 55%)',
      }}
    >
      <Paper
        elevation={4}
        sx={{
          width: '100%',
          maxWidth: 880,
          borderRadius: 3,
          overflow: 'hidden',
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', md: '1.1fr 1fr' },
        }}
      >
        {/* Left: form */}
        <Box sx={{ p: { xs: 3, sm: 4 }, borderRight: { md: 1, xs: 0 }, borderColor: 'divider' }}>
          <Stack spacing={{ xs: 2, sm: 2.5 }}>
            <Box>
              <Typography
                variant="h4"
                sx={{
                  fontWeight: 900,
                  fontSize: { xs: '1.5rem', sm: '1.75rem' },
                  mb: 0.5,
                }}
              >
                {isLogin ? 'Welkom terug' : 'Account aanmaken'}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Log in om je stageplanning, bestanden en team te beheren.
              </Typography>
            </Box>

            <Typography variant="caption" color="text.secondary">
              Backend: <b>{API}</b>
            </Typography>

            {/* Identifier / email */}
            <TextField
              label={isLogin ? 'E-mailadres of gebruikersnaam' : 'E-mailadres'}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              fullWidth
              autoComplete={isLogin ? 'username' : 'email'}
            />

            {/* Extra velden bij register */}
            {!isLogin && (
              <>
                <TextField
                  label="Gebruikersnaam"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  fullWidth
                  autoComplete="username"
                />
                <Stack
                  direction={{ xs: 'column', sm: 'row' }}
                  spacing={{ xs: 1.5, sm: 2 }}
                >
                  <TextField
                    label="Voornaam"
                    value={firstName}
                    onChange={(e) => setFirstName(e.target.value)}
                    fullWidth
                  />
                  <TextField
                    label="Achternaam"
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                    fullWidth
                  />
                </Stack>
              </>
            )}

            {/* Wachtwoord */}
            <TextField
              label="Wachtwoord"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              fullWidth
              autoComplete={isLogin ? 'current-password' : 'new-password'}
            />

            {!isLogin && (
              <TextField
                label="Herhaal wachtwoord"
                type="password"
                value={passwordConfirm}
                onChange={(e) => setPasswordConfirm(e.target.value)}
                fullWidth
                autoComplete="new-password"
              />
            )}

            {/* Forgot password hint (UI only) */}
            {isLogin && (
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2" color="text.secondary">
                  Wachtwoord vergeten?
                </Typography>
                <Button
                  size="small"
                  variant="text"
                  onClick={() => {
                    setForgotMode(true)
                    setInfo(
                      'Neem contact op met je docent of stagebegeleider om je wachtwoord te laten resetten.',
                    )
                  }}
                  disabled={busy}
                >
                  Toon instructies
                </Button>
              </Box>
            )}

            {/* Meldingen */}
            {info && (
              <Alert severity="success">
                {info}
              </Alert>
            )}
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
            {forgotMode && (
              <Alert severity="info">
                Wachtwoord vergeten? In dit systeem wordt je account centraal beheerd.
                Neem contact op met je docent of stagebegeleider om je wachtwoord te laten resetten.
              </Alert>
            )}

            {/* Actieknoppen */}
            <Stack
              direction={{ xs: 'column', sm: 'row' }}
              spacing={1.5}
              justifyContent="space-between"
              alignItems={{ xs: 'stretch', sm: 'center' }}
            >
              <Button
                variant="text"
                onClick={() => {
                  setMode((m) => (m === 'login' ? 'register' : 'login'))
                  setError(null)
                  setInfo(null)
                  setValidationIssues([])
                  setForgotMode(false)
                }}
                disabled={busy}
              >
                {isLogin ? 'Account maken' : 'Ik heb al een account'}
              </Button>
              <Button
                variant="contained"
                onClick={() => void submit()}
                disabled={
                  busy ||
                  !email ||
                  !password ||
                  (!isLogin && (!username || !firstName || !lastName || !passwordConfirm))
                }
                sx={{ minWidth: { xs: '100%', sm: 140 } }}
              >
                {isLogin ? 'Inloggen' : 'Registreren'}
              </Button>
            </Stack>
          </Stack>
        </Box>

        {/* Right: branding / uitleg */}
        <Box
          sx={{
            display: { xs: 'none', md: 'flex' },
            flexDirection: 'column',
            justifyContent: 'space-between',
            p: 4,
            background:
              'linear-gradient(140deg, rgba(25,118,210,0.9), rgba(156,39,176,0.9))',
            color: 'common.white',
          }}
        >
          <Box>
            <Typography
              variant="h4"
              sx={{ fontWeight: 900, mb: 1 }}
            >
              Stage Planner
            </Typography>
            <Typography variant="body2" sx={{ opacity: 0.9, mb: 3 }}>
              Plan je week, beheer je taken, deel bestanden en werk samen met je mentor en
              begeleider in één overzichtelijke workspace.
            </Typography>
          </Box>
          <Box>
            <Typography variant="overline" sx={{ opacity: 0.8 }}>
              Tip
            </Typography>
            <Typography variant="body2">
              Gebruik je schoolmail of vaste gebruikersnaam om in te loggen. Ben je je
              wachtwoord kwijt? Gebruik de instructies op deze pagina of neem contact op met je
              docent.
            </Typography>
          </Box>
        </Box>
      </Paper>
    </Box>
  )
}


