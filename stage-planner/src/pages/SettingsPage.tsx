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
    startPage,
    setStartPage,
    weekViewMode,
    setWeekViewMode,
    defaultTaskMinutes,
    setDefaultTaskMinutes,
    defaultPriority,
    setDefaultPriority,
    defaultStatus,
    setDefaultStatus,
    workdayStart,
    setWorkdayStart,
    workdayEnd,
    setWorkdayEnd,
    compactMode,
    setCompactMode,
    reduceMotion,
    setReduceMotion,
    autoExtractTextOnOpen,
    setAutoExtractTextOnOpen,
    ocrLanguage,
    setOcrLanguage,
    errorLoggingEnabled,
    setErrorLoggingEnabled,
    errorLogRetentionDays,
    setErrorLogRetentionDays,
    errorLogMaxEntries,
    setErrorLogMaxEntries,
    idleLogoutMinutes,
    setIdleLogoutMinutes,
  } = useSettings()
  const { token, user, login } = useAuth()

  const settingsSnapshot = useMemo(
    () => ({
      mode,
      weekStart,
      timeFormat,
      startPage,
      weekViewMode,
      defaultTaskMinutes,
      defaultPriority,
      defaultStatus,
      workdayStart,
      workdayEnd,
      compactMode,
      reduceMotion,
      autoExtractTextOnOpen,
      ocrLanguage,
      errorLoggingEnabled,
      errorLogRetentionDays,
      errorLogMaxEntries,
      idleLogoutMinutes,
    }),
    [
      mode,
      weekStart,
      timeFormat,
      startPage,
      weekViewMode,
      defaultTaskMinutes,
      defaultPriority,
      defaultStatus,
      workdayStart,
      workdayEnd,
      compactMode,
      reduceMotion,
      autoExtractTextOnOpen,
      ocrLanguage,
      errorLoggingEnabled,
      errorLogRetentionDays,
      errorLogMaxEntries,
      idleLogoutMinutes,
    ],
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
          <Typography sx={{ fontWeight: 900 }}>Navigatie</Typography>
          <TextField
            select
            label="Startpagina na login"
            value={startPage}
            onChange={(e) => setStartPage(e.target.value as any)}
            sx={{ maxWidth: 360 }}
            helperText="Waar je standaard landt na inloggen (en bij ‘/’)."
          >
            <MenuItem value="/dashboard">Dashboard</MenuItem>
            <MenuItem value="/planning">Planning</MenuItem>
            <MenuItem value="/week">Week</MenuItem>
            <MenuItem value="/taken">Taken</MenuItem>
            <MenuItem value="/bestanden">Bestanden</MenuItem>
            <MenuItem value="/notities">Notities</MenuItem>
          </TextField>
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
          <TextField
            select
            label="Weekweergave"
            value={weekViewMode}
            onChange={(e) => setWeekViewMode(e.target.value as any)}
            sx={{ maxWidth: 280 }}
            helperText="‘Werkweek’ toont altijd maandag t/m vrijdag."
          >
            <MenuItem value="full">Volledige week (7 dagen)</MenuItem>
            <MenuItem value="workweek">Werkweek (5 dagen)</MenuItem>
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
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              select
              label="Standaard prioriteit (nieuw item)"
              value={defaultPriority}
              onChange={(e) => setDefaultPriority(e.target.value as any)}
              fullWidth
            >
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
            </TextField>
            <TextField
              select
              label="Standaard status (nieuw item)"
              value={defaultStatus}
              onChange={(e) => setDefaultStatus(e.target.value as any)}
              fullWidth
            >
              <MenuItem value="todo">Todo</MenuItem>
              <MenuItem value="in_progress">In progress</MenuItem>
              <MenuItem value="done">Done</MenuItem>
            </TextField>
          </Stack>
          <Typography variant="body2" color="text.secondary">
            Deze instellingen worden lokaal opgeslagen in je browser.
          </Typography>
        </Stack>
      </Paper>

      <Paper sx={{ p: 2 }}>
        <Stack spacing={2}>
          <Typography sx={{ fontWeight: 900 }}>Bestanden / preview</Typography>
          <FormControlLabel
            control={<Switch checked={autoExtractTextOnOpen} onChange={(e) => setAutoExtractTextOnOpen(e.target.checked)} />}
            label="Automatisch tekst extract/OCR bij openen (PDF/afbeeldingen)"
          />
          <TextField
            label="OCR taal (Tesseract)"
            value={ocrLanguage}
            onChange={(e) => setOcrLanguage(e.target.value)}
            sx={{ maxWidth: 360 }}
            helperText="Voorbeelden: eng, nld, deu, fra. (Tesseract downloadt taaldata bij eerste gebruik.)"
          />
        </Stack>
      </Paper>

      <Paper sx={{ p: 2 }}>
        <Stack spacing={2}>
          <Typography sx={{ fontWeight: 900 }}>Privacy / diagnose</Typography>
          <FormControlLabel
            control={<Switch checked={errorLoggingEnabled} onChange={(e) => setErrorLoggingEnabled(e.target.checked)} />}
            label="Fouten lokaal loggen (voor troubleshooting / admin)"
          />
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              label="Bewaar errors (dagen)"
              type="number"
              value={errorLogRetentionDays}
              onChange={(e) => setErrorLogRetentionDays(Math.max(0, Math.min(365, Number(e.target.value) || 0)))}
              inputProps={{ min: 0, max: 365, step: 1 }}
              fullWidth
              helperText="0 = oneindig bewaren"
              disabled={!errorLoggingEnabled}
            />
            <TextField
              label="Max errors (aantal)"
              type="number"
              value={errorLogMaxEntries}
              onChange={(e) => setErrorLogMaxEntries(Math.max(50, Math.min(5000, Number(e.target.value) || 500)))}
              inputProps={{ min: 50, max: 5000, step: 50 }}
              fullWidth
              helperText="Oudste entries worden verwijderd zodra je erover gaat."
              disabled={!errorLoggingEnabled}
            />
          </Stack>
        </Stack>
      </Paper>

      <Paper sx={{ p: 2 }}>
        <Stack spacing={2}>
          <Typography sx={{ fontWeight: 900 }}>Sessie / beveiliging</Typography>
          <TextField
            select
            label="Automatisch uitloggen bij inactiviteit"
            value={idleLogoutMinutes}
            onChange={(e) => setIdleLogoutMinutes(Number(e.target.value) || 0)}
            sx={{ maxWidth: 360 }}
            helperText="Handig op gedeelde pc. Let op: token-expiry blijft altijd gelden."
          >
            <MenuItem value={0}>Nooit</MenuItem>
            <MenuItem value={15}>15 minuten</MenuItem>
            <MenuItem value={30}>30 minuten</MenuItem>
            <MenuItem value={60}>60 minuten</MenuItem>
            <MenuItem value={120}>120 minuten</MenuItem>
          </TextField>
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



