import { Alert, Box, Button, FormControlLabel, MenuItem, Paper, Stack, Switch, TextField, Typography } from '@mui/material'
import { useEffect, useMemo, useRef, useState } from 'react'
import { apiFetch } from '../api/client'
import { useSettings, type StartPage } from '../app/settings'
import { useAuth } from '../auth/auth'
import { WorkspaceSelector } from '../components/WorkspaceSelector'
import { useWorkspace } from '../hooks/useWorkspace'
import { db, type AppErrorLog } from '../db/db'

export function SettingsPage() {
  const { currentWorkspace } = useWorkspace()
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
    stageStart,
    setStageStart,
    stageEnd,
    setStageEnd,
    stageHolidaysJson,
    setStageHolidaysJson,
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

  const holidaysText = useMemo(() => {
    try {
      const arr = JSON.parse(stageHolidaysJson || '[]') as string[]
      return (arr || []).join('\n')
    } catch {
      return ''
    }
  }, [stageHolidaysJson])

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
      stageStart,
      stageEnd,
      stageHolidaysJson,
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
  const lastSentRef = useRef<Record<string, unknown> | null>(null)
  const debounceRef = useRef<number | null>(null)

  // Best-effort: log settings changes to backend audit (only when logged in)
  useEffect(() => {
    if (!token) return
    if (!lastSentRef.current) {
      lastSentRef.current = settingsSnapshot
      return
    }

    const prev = lastSentRef.current as Record<string, unknown>
    const next = settingsSnapshot as Record<string, unknown>
    const changes: Record<string, { from: unknown; to: unknown }> = {}
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
    firstName: user?.firstName ?? '',
    lastName: user?.lastName ?? '',
    notifyDeadlineEmail: user?.notifyDeadlineEmail ?? true,
  })

  const [pw, setPw] = useState({ current: '', next: '', next2: '' })
  const [pwMsg, setPwMsg] = useState<string | null>(null)
  const [pwErr, setPwErr] = useState<string | null>(null)
  const [errorLogs, setErrorLogs] = useState<AppErrorLog[]>([])
  const [errorLogsLoading, setErrorLogsLoading] = useState(false)



  useEffect(() => {
    setProfile({
      username: user?.username ?? '',
      firstName: user?.firstName ?? '',
      lastName: user?.lastName ?? '',
      notifyDeadlineEmail: user?.notifyDeadlineEmail ?? true,
    })
  }, [user?.username, user?.firstName, user?.lastName, user?.notifyDeadlineEmail])

  async function refreshErrorLogs() {
    if (!errorLoggingEnabled) {
      setErrorLogs([])
      return
    }
    setErrorLogsLoading(true)
    try {
      const items = await db.errors.orderBy('createdAt').reverse().limit(50).toArray()
      setErrorLogs(items)
    } catch {
      setErrorLogs([])
    } finally {
      setErrorLogsLoading(false)
    }
  }

  async function clearErrorLogs() {
    try {
      await db.errors.clear()
      setErrorLogs([])
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    void refreshErrorLogs()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [errorLoggingEnabled])

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
          notifyDeadlineEmail: profile.notifyDeadlineEmail,
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
    <Box sx={{ display: 'grid', gap: { xs: 1.5, sm: 2 } }}>
      <Typography variant="h5" sx={{ fontWeight: 800, fontSize: { xs: '1.125rem', sm: '1.25rem' } }}>
        Instellingen
      </Typography>

      <Paper sx={{ p: { xs: 1.5, sm: 2 } }}>
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

      <Paper sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Stack spacing={{ xs: 1.5, sm: 2 }}>
          <Typography sx={{ fontWeight: 900, fontSize: { xs: '0.875rem', sm: '1rem' } }}>Navigatie</Typography>
          <TextField
            select
            label="Startpagina na login"
            value={startPage}
            onChange={(e) => setStartPage(e.target.value as StartPage)}
            size="small"
            sx={{ width: { xs: '100%', sm: 'auto' }, maxWidth: { xs: '100%', sm: 360 } }}
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
            onChange={(e) => setWeekStart(e.target.value as 'monday' | 'sunday')}
            sx={{ maxWidth: 280 }}
          >
            <MenuItem value="monday">Maandag</MenuItem>
            <MenuItem value="sunday">Zondag</MenuItem>
          </TextField>
          <TextField
            select
            label="Tijd formaat"
            value={timeFormat}
            onChange={(e) => setTimeFormat(e.target.value as '24h' | '12h')}
            sx={{ maxWidth: 280 }}
          >
            <MenuItem value="24h">24-uurs (14:30)</MenuItem>
            <MenuItem value="12h">12-uurs (2:30 PM)</MenuItem>
          </TextField>
          <TextField
            select
            label="Weekweergave"
            value={weekViewMode}
            onChange={(e) => setWeekViewMode(e.target.value as 'full' | 'workweek')}
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
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              label="Stage start"
              type="date"
              value={stageStart}
              onChange={(e) => setStageStart(e.target.value)}
              InputLabelProps={{ shrink: true }}
              fullWidth
            />
            <TextField
              label="Stage einde"
              type="date"
              value={stageEnd}
              onChange={(e) => setStageEnd(e.target.value)}
              InputLabelProps={{ shrink: true }}
              fullWidth
            />
          </Stack>
          <TextField
            label="Vakantie / feestdagen (1 per lijn)"
            value={holidaysText}
            onChange={(e) => {
              const raw = e.target.value
              const dates = raw
                .split('\n')
                .map((d) => d.trim())
                .filter(Boolean)
                .filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d))
              setStageHolidaysJson(JSON.stringify(dates))
            }}
            helperText="Gebruik formaat YYYY-MM-DD. Deze dagen tellen nooit als werkdag."
            minRows={3}
            multiline
          />
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
              onChange={(e) => setDefaultPriority(e.target.value as 'low' | 'medium' | 'high')}
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
              onChange={(e) => setDefaultStatus(e.target.value as 'todo' | 'in_progress' | 'done')}
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
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }} justifyContent="space-between">
            <Typography variant="body2" color="text.secondary">
              Laatste fouten (max 50)
            </Typography>
            <Stack direction="row" spacing={1}>
              <Button variant="outlined" size="small" onClick={() => void refreshErrorLogs()} disabled={!errorLoggingEnabled || errorLogsLoading}>
                Refresh
              </Button>
              <Button variant="outlined" size="small" color="error" onClick={() => void clearErrorLogs()} disabled={!errorLoggingEnabled}>
                Wis logs
              </Button>
            </Stack>
          </Stack>
          {errorLoggingEnabled && errorLogs.length > 0 && (
            <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, maxHeight: 240, overflow: 'auto', p: 1 }}>
              {errorLogs.map((entry) => (
                <Box key={entry.id} sx={{ py: 0.5, borderBottom: '1px dashed', borderColor: 'divider' }}>
                  <Typography variant="body2" sx={{ fontWeight: 700 }}>
                    {entry.source} • {new Date(entry.createdAt).toLocaleString()}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {entry.message}
                  </Typography>
                </Box>
              ))}
            </Box>
          )}
          {errorLoggingEnabled && !errorLogsLoading && errorLogs.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              Geen fouten gelogd.
            </Typography>
          )}
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
              <FormControlLabel
                control={
                  <Switch
                    checked={profile.notifyDeadlineEmail}
                    onChange={(e) => setProfile((p) => ({ ...p, notifyDeadlineEmail: e.target.checked }))}
                  />
                }
                label="E-mail notificaties bij deadlines"
              />
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
                value={currentWorkspace?.name || ''}
                disabled
                helperText="Je actieve groep bepaalt welke cloud data je ziet. Je persoonlijke groep = je eigen planner."
              />
              <Box sx={{ maxWidth: 360 }}>
                <WorkspaceSelector />
              </Box>
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



