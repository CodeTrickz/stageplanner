import { Alert, Box, Button, FormControlLabel, MenuItem, Paper, Stack, Switch, TextField, Typography } from '@mui/material'
import { useEffect, useMemo, useRef, useState } from 'react'
import { apiFetch } from '../api/client'
import { useSettings } from '../app/settings'
import { useAuth } from '../auth/auth'

export function SettingsPage() {
  const {
    mode,
    toggleMode,
    weekStart,
    setWeekStart,
    timeFormat,
    setTimeFormat,
    defaultTaskMinutes,
    setDefaultTaskMinutes,
    workdayStart,
    setWorkdayStart,
    workdayEnd,
    setWorkdayEnd,
    compactMode,
    setCompactMode,
    reduceMotion,
    setReduceMotion,
  } = useSettings()
  const { token, user, login } = useAuth()

  const settingsSnapshot = useMemo(
    () => ({
      mode,
      weekStart,
      timeFormat,
      defaultTaskMinutes,
      workdayStart,
      workdayEnd,
      compactMode,
      reduceMotion,
    }),
    [mode, weekStart, timeFormat, defaultTaskMinutes, workdayStart, workdayEnd, compactMode, reduceMotion],
  )
  const lastSentRef = useRef<any>(null)
  const debounceRef = useRef<number | null>(null)

  // Best-effort: log settings changes to backend audit (only when logged in)
  useEffect(() => {
    if (!token) return
    if (!lastSentRef.current) {
      lastSentRef.current = settingsSnapshot
      return
    }

    const prev = lastSentRef.current as any
    const next = settingsSnapshot as any
    const changes: Record<string, any> = {}
    for (const k of Object.keys(next)) {
      if (prev[k] !== next[k]) changes[k] = { from: prev[k], to: next[k] }
    }
    if (Object.keys(changes).length === 0) return

    if (debounceRef.current) window.clearTimeout(debounceRef.current)
    debounceRef.current = window.setTimeout(() => {
      // don't await: avoid blocking UI
      void apiFetch('/audit/settings', {
        method: 'POST',
        token,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ changes }),
      }).catch(() => {
        // ignore (offline etc)
      })
      lastSentRef.current = settingsSnapshot
    }, 800)

    return () => {
      if (debounceRef.current) window.clearTimeout(debounceRef.current)
    }
  }, [token, settingsSnapshot])

  const [meError, setMeError] = useState<string | null>(null)
  const [meOk, setMeOk] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const [profile, setProfile] = useState({
    username: user?.username ?? '',
    firstName: (user as any)?.firstName ?? '',
    lastName: (user as any)?.lastName ?? '',
  })

  const [pw, setPw] = useState({ current: '', next: '', next2: '' })
  const [pwMsg, setPwMsg] = useState<string | null>(null)
  const [pwErr, setPwErr] = useState<string | null>(null)



  useEffect(() => {
    setProfile({
      username: user?.username ?? '',
      firstName: (user as any)?.firstName ?? '',
      lastName: (user as any)?.lastName ?? '',
    })
  }, [user?.username, (user as any)?.firstName, (user as any)?.lastName])

  async function refreshMe() {
    if (!token) return
    const data = await apiFetch('/me', { token })
    if (data?.user?.id) login(token, data.user)
  }

  async function saveProfile() {
    if (!token) return
    setMeError(null)
    setMeOk(null)
    setBusy(true)
    try {
      const data = await apiFetch('/me', {
        method: 'PATCH',
        token,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          username: profile.username?.trim() || undefined,
          firstName: profile.firstName?.trim() || undefined,
          lastName: profile.lastName?.trim() || undefined,
        }),
      })
      if (data?.user?.id) login(token, data.user)
      setMeOk('Account gegevens opgeslagen.')
    } catch (e) {
      setMeError(e instanceof Error ? e.message : 'save_failed')
    } finally {
      setBusy(false)
    }
  }

  async function changePassword() {
    if (!token) return
    setPwErr(null)
    setPwMsg(null)
    setBusy(true)
    try {
      await apiFetch('/me/password', {
        method: 'POST',
        token,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          currentPassword: pw.current,
          newPassword: pw.next,
          newPasswordConfirm: pw.next2,
        }),
      })
      setPwMsg('Wachtwoord gewijzigd.')
      setPw({ current: '', next: '', next2: '' })
      await refreshMe()
    } catch (e) {
      setPwErr(e instanceof Error ? e.message : 'password_change_failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      <Typography variant="h5" sx={{ fontWeight: 800 }}>
        Instellingen
      </Typography>

      <Paper sx={{ p: 2 }}>
        <Stack spacing={2}>
          <FormControlLabel
            control={<Switch checked={mode === 'dark'} onChange={toggleMode} />}
            label="Dark mode"
          />
          <FormControlLabel
            control={<Switch checked={compactMode} onChange={(e) => setCompactMode(e.target.checked)} />}
            label="Compacte layout (meer info op 1 scherm)"
          />
          <FormControlLabel
            control={<Switch checked={reduceMotion} onChange={(e) => setReduceMotion(e.target.checked)} />}
            label="Minder animaties (reduce motion)"
          />
        </Stack>
      </Paper>

      <Paper sx={{ p: 2 }}>
        <Stack spacing={2}>
          <Typography sx={{ fontWeight: 900 }}>Planning voorkeuren</Typography>
          <TextField
            select
            label="Week start"
            value={weekStart}
            onChange={(e) => setWeekStart(e.target.value as any)}
            sx={{ maxWidth: 280 }}
          >
            <MenuItem value="monday">Maandag</MenuItem>
            <MenuItem value="sunday">Zondag</MenuItem>
          </TextField>
          <TextField
            select
            label="Tijd formaat"
            value={timeFormat}
            onChange={(e) => setTimeFormat(e.target.value as any)}
            sx={{ maxWidth: 280 }}
          >
            <MenuItem value="24h">24-uurs (14:30)</MenuItem>
            <MenuItem value="12h">12-uurs (2:30 PM)</MenuItem>
          </TextField>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              label="Werkdag start"
              type="time"
              value={workdayStart}
              onChange={(e) => setWorkdayStart(e.target.value)}
              InputLabelProps={{ shrink: true }}
              fullWidth
            />
            <TextField
              label="Werkdag einde"
              type="time"
              value={workdayEnd}
              onChange={(e) => setWorkdayEnd(e.target.value)}
              InputLabelProps={{ shrink: true }}
              fullWidth
            />
          </Stack>
          <TextField
            label="Standaard taakduur (minuten)"
            type="number"
            value={defaultTaskMinutes}
            onChange={(e) => setDefaultTaskMinutes(Math.min(8 * 60, Math.max(5, Number(e.target.value) || 60)))}
            inputProps={{ min: 5, max: 480, step: 5 }}
            sx={{ maxWidth: 280 }}
            helperText="Bij “Nieuw item” wordt deze duur gebruikt."
          />
          <Typography variant="body2" color="text.secondary">
            Deze instellingen worden lokaal opgeslagen in je browser.
          </Typography>
        </Stack>
      </Paper>

      <Paper sx={{ p: 2 }}>
        <Stack spacing={2}>
          <Typography sx={{ fontWeight: 900 }}>Account</Typography>
          {!token && <Alert severity="info">Login om je account te beheren.</Alert>}
          {token && (
            <>
              <TextField label="Email" value={user?.email ?? ''} disabled />
              <TextField
                label="Username"
                value={profile.username}
                onChange={(e) => setProfile((p) => ({ ...p, username: e.target.value }))}
              />
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
                <TextField
                  label="Voornaam"
                  value={profile.firstName}
                  onChange={(e) => setProfile((p) => ({ ...p, firstName: e.target.value }))}
                  fullWidth
                />
                <TextField
                  label="Achternaam"
                  value={profile.lastName}
                  onChange={(e) => setProfile((p) => ({ ...p, lastName: e.target.value }))}
                  fullWidth
                />
              </Stack>
              <TextField
                label="Groep"
                value={(user as any)?.activeGroupName || (user as any)?.activeGroupId || ''}
                disabled
                helperText="Je actieve groep bepaalt welke cloud data je ziet. Je persoonlijke groep = je eigen planner."
              />
              <Stack direction="row" spacing={1} justifyContent="flex-end">
                <Button variant="outlined" disabled={busy} onClick={() => void refreshMe()}>
                  Refresh
                </Button>
                <Button variant="contained" disabled={busy} onClick={() => void saveProfile()}>
                  Opslaan
                </Button>
              </Stack>
              {meOk && <Alert severity="success">{meOk}</Alert>}
              {meError && <Alert severity="error">{meError}</Alert>}
            </>
          )}
        </Stack>
      </Paper>



      <Paper sx={{ p: 2 }}>
        <Stack spacing={2}>
          <Typography sx={{ fontWeight: 900 }}>Wachtwoord wijzigen</Typography>
          {!token && <Alert severity="info">Login om je wachtwoord te wijzigen.</Alert>}
          {token && (
            <>
              <TextField
                label="Huidig wachtwoord"
                type="password"
                value={pw.current}
                onChange={(e) => setPw((p) => ({ ...p, current: e.target.value }))}
              />
              <TextField
                label="Nieuw wachtwoord"
                type="password"
                value={pw.next}
                onChange={(e) => setPw((p) => ({ ...p, next: e.target.value }))}
                helperText="Minstens 8 tekens."
              />
              <TextField
                label="Nieuw wachtwoord (bevestig)"
                type="password"
                value={pw.next2}
                onChange={(e) => setPw((p) => ({ ...p, next2: e.target.value }))}
              />
              <Stack direction="row" spacing={1} justifyContent="flex-end">
                <Button
                  variant="contained"
                  disabled={busy || !pw.current || !pw.next || !pw.next2}
                  onClick={() => void changePassword()}
                >
                  Wijzig wachtwoord
                </Button>
              </Stack>
              {pwMsg && <Alert severity="success">{pwMsg}</Alert>}
              {pwErr && <Alert severity="error">{pwErr}</Alert>}
            </>
          )}
        </Stack>
      </Paper>
    </Box>
  )
}



