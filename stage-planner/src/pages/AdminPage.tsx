import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline'
import DownloadIcon from '@mui/icons-material/Download'
import EditOutlinedIcon from '@mui/icons-material/EditOutlined'
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Paper,
  Stack,
  TextField,
  Typography,
  useMediaQuery,
  useTheme,
} from '@mui/material'
import { useEffect, useMemo, useState } from 'react'
import { useAuth } from '../auth/auth'
import { API_BASE, apiFetch } from '../api/client'
import { useLiveQuery } from 'dexie-react-hooks'
import { db } from '../db/db'

const API = API_BASE

type AdminUser = {
  id: string
  email: string
  username: string
  firstName: string
  lastName: string
  isAdmin: boolean
  emailVerified: boolean
  createdAt: number
  updatedAt: number
}

export function AdminPage() {
  const theme = useTheme()
  const fullScreenDialog = useMediaQuery(theme.breakpoints.down('sm'))
  const { token, user } = useAuth()
  const [users, setUsers] = useState<AdminUser[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState<(AdminUser & { newPassword: string }) | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [create, setCreate] = useState({
    email: '',
    username: '',
    firstName: '',
    lastName: '',
    password: '',
    isAdmin: false,
    emailVerified: true,
  })

  const isAdmin = !!user?.isAdmin

  const [audit, setAudit] = useState<Record<string, unknown>[] | null>(null)
  const [backendErrors, setBackendErrors] = useState<Record<string, unknown>[] | null>(null)
  const [frontendOpenId, setFrontendOpenId] = useState<number | null>(null)
  const [backendOpenIdx, setBackendOpenIdx] = useState<number | null>(null)
  const [auditPage, setAuditPage] = useState(0)
  const [auditTotal, setAuditTotal] = useState<number | null>(null)
  const [backendErrPage, setBackendErrPage] = useState(0)
  const [backendErrTotal, setBackendErrTotal] = useState<number | null>(null)
  const [frontendErrPage, setFrontendErrPage] = useState(0)
  const [frontendErrTotal, setFrontendErrTotal] = useState<number | null>(null)

  const PAGE_SIZE = 10

  const frontendErrors = useLiveQuery(async () => {
    const total = await db.errors.count()
    const list = await db.errors
      .orderBy('createdAt')
      .reverse()
      .offset(frontendErrPage * PAGE_SIZE)
      .limit(PAGE_SIZE)
      .toArray()
    setFrontendErrTotal(total)
    return list
  }, [frontendErrPage])

  async function load() {
    if (!token) return
    setError(null)
    setBusy(true)
    try {
      const res = await fetch(`${API}/admin/users`, {
        headers: { authorization: `Bearer ${token}` },
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data?.error || 'load_failed')
      setUsers(data.users as AdminUser[])

      const a = await apiFetch(`/admin/audit?limit=${PAGE_SIZE}&offset=${auditPage * PAGE_SIZE}`, { token })
      setAudit(a.logs ?? [])
      setAuditTotal(typeof a.total === 'number' ? a.total : null)

      const be = await apiFetch(`/admin/errors?limit=${PAGE_SIZE}&offset=${backendErrPage * PAGE_SIZE}`, { token })
      setBackendErrors(be.errors ?? [])
      setBackendErrTotal(typeof be.total === 'number' ? be.total : null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'load_failed')
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, auditPage, backendErrPage])

  const sorted = useMemo(() => {
    if (!users) return []
    return users.slice().sort((a, b) => b.createdAt - a.createdAt)
  }, [users])

  async function save() {
    if (!token || !draft) return
    setError(null)
    setBusy(true)
    try {
      const res = await fetch(`${API}/admin/users/${draft.id}`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: JSON.stringify({
          email: draft.email,
          username: draft.username,
          firstName: draft.firstName,
          lastName: draft.lastName,
          isAdmin: draft.isAdmin,
          emailVerified: draft.emailVerified,
          newPassword: draft.newPassword ? draft.newPassword : undefined,
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data?.error || 'save_failed')
      setOpen(false)
      setDraft(null)
      await load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'save_failed')
    } finally {
      setBusy(false)
    }
  }

  async function createUser() {
    if (!token) return
    setError(null)
    setBusy(true)
    try {
      const res = await fetch(`${API}/admin/users`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: JSON.stringify(create),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data?.error || 'create_failed')
      setCreateOpen(false)
      setCreate({
        email: '',
        username: '',
        firstName: '',
        lastName: '',
        password: '',
        isAdmin: false,
        emailVerified: true,
      })
      await load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'create_failed')
    } finally {
      setBusy(false)
    }
  }

  async function remove(id: string) {
    if (!token) return
    if (!confirm('Gebruiker verwijderen?')) return
    setError(null)
    setBusy(true)
    try {
      const res = await fetch(`${API}/admin/users/${id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data?.error || 'delete_failed')
      await load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'delete_failed')
    } finally {
      setBusy(false)
    }
  }

  async function downloadAudit(format: 'csv' | 'json' = 'csv') {
    if (!token) return
    setError(null)
    setBusy(true)
    try {
      const res = await fetch(`${API}/admin/audit/download?format=${encodeURIComponent(format)}&limit=5000`, {
        headers: { authorization: `Bearer ${token}` },
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data?.error || 'download_failed')
      }
      const blob = await res.blob()
      const cd = res.headers.get('content-disposition') || ''
      const m = /filename="([^"]+)"/.exec(cd)
      const filename = (m?.[1] || `audit.${format}`).trim()

      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      try {
        if (a.parentNode) a.parentNode.removeChild(a)
      } catch {
        // ignore
      }
      setTimeout(() => URL.revokeObjectURL(url), 0)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'download_failed')
    } finally {
      setBusy(false)
    }
  }

  async function downloadBackendErrors(format: 'ndjson' | 'json' = 'ndjson') {
    if (!token) return
    setError(null)
    setBusy(true)
    try {
      const res = await fetch(`${API}/admin/errors/download?format=${encodeURIComponent(format)}`, {
        headers: { authorization: `Bearer ${token}` },
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data?.error || 'download_failed')
      }
      const blob = await res.blob()
      const cd = res.headers.get('content-disposition') || ''
      const m = /filename="([^"]+)"/.exec(cd)
      const filename = (m?.[1] || `backend-errors.${format}`).trim()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      try {
        if (a.parentNode) a.parentNode.removeChild(a)
      } catch {
        // ignore
      }
      setTimeout(() => URL.revokeObjectURL(url), 0)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'download_failed')
    } finally {
      setBusy(false)
    }
  }

  async function downloadFrontendErrorsJson() {
    try {
      const blob = new Blob([JSON.stringify({ errors: frontendErrors ?? [] }, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `frontend-errors-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
      document.body.appendChild(a)
      a.click()
      try {
        if (a.parentNode) a.parentNode.removeChild(a)
      } catch {
        // ignore
      }
      setTimeout(() => URL.revokeObjectURL(url), 0)
    } catch {
      // ignore
    }
  }

  async function clearFrontendErrors() {
    try {
      if (!frontendErrors?.length) return
      await db.errors.bulkDelete(frontendErrors.map((e) => e.id!).filter(Boolean))
    } catch {
      // ignore
    }
  }

  if (!isAdmin) {
    return (
      <Alert severity="error">
        Forbidden: je bent geen admin.
      </Alert>
    )
  }

  return (
    <Box sx={{ display: 'grid', gap: { xs: 1.5, sm: 2 } }}>
      <Typography variant="h5" sx={{ fontWeight: 800, fontSize: { xs: '1.125rem', sm: '1.25rem' } }}>
        Admin – gebruikers
      </Typography>

      <Paper sx={{ p: 2 }}>
        <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between">
          <Typography variant="body2" color="text.secondary">
            Default admin: <b>admin@app.be</b> / <b>admin</b>
          </Typography>
          <Stack direction="row" spacing={1}>
            <Button variant="contained" onClick={() => setCreateOpen(true)} disabled={busy}>
              Nieuwe gebruiker
            </Button>
            <Button variant="outlined" onClick={() => void load()} disabled={busy}>
              Refresh
            </Button>
          </Stack>
        </Stack>
      </Paper>

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }} justifyContent="space-between" sx={{ mb: 1 }}>
          <Typography sx={{ fontWeight: 900 }}>
            Audit log ({PAGE_SIZE} per pagina{auditTotal != null ? `, totaal ${auditTotal}` : ''})
          </Typography>
          <Stack direction="row" spacing={1}>
            <Button
              variant="outlined"
              startIcon={<DownloadIcon />}
              disabled={busy}
              onClick={() => void downloadAudit('csv')}
            >
              Download CSV
            </Button>
            <Button
              variant="outlined"
              startIcon={<DownloadIcon />}
              disabled={busy}
              onClick={() => void downloadAudit('json')}
            >
              Download JSON
            </Button>
          </Stack>
        </Stack>
        <Stack direction="row" spacing={1} justifyContent="flex-end" sx={{ mb: 1 }}>
          <Button variant="outlined" disabled={busy || auditPage === 0} onClick={() => setAuditPage((p) => Math.max(0, p - 1))}>
            Vorige
          </Button>
          <Button
            variant="outlined"
            disabled={busy || (auditTotal != null ? (auditPage + 1) * PAGE_SIZE >= auditTotal : false)}
            onClick={() => setAuditPage((p) => p + 1)}
          >
            Volgende
          </Button>
          <Typography variant="body2" color="text.secondary" sx={{ alignSelf: 'center' }}>
            Pagina {auditPage + 1}
          </Typography>
        </Stack>
        {!audit && <Alert severity="info">Laden…</Alert>}
        {audit && audit.length === 0 && <Alert severity="info">Geen logs.</Alert>}
        {audit && audit.length > 0 && (
          <Stack spacing={1}>
            {audit.map((l, idx) => {
              const id = typeof l.id === 'string' ? l.id : typeof l.id === 'number' ? String(l.id) : String(idx)
              const createdAt = typeof l.createdAt === 'number' ? l.createdAt : typeof l.createdAt === 'string' ? Number(l.createdAt) : Date.now()
              const actorEmail = typeof l.actorEmail === 'string' ? l.actorEmail : undefined
              const actorUsername = typeof l.actorUsername === 'string' ? l.actorUsername : undefined
              const actorUserId = typeof l.actorUserId === 'string' ? l.actorUserId : undefined
              const action = typeof l.action === 'string' ? l.action : 'unknown'
              const resourceType = typeof l.resourceType === 'string' ? l.resourceType : 'unknown'
              const resourceId = typeof l.resourceId === 'string' ? l.resourceId : String(l.resourceId ?? '')
              return (
                <Paper key={id} variant="outlined" sx={{ p: 1.25 }}>
                  <Typography sx={{ fontWeight: 800 }}>
                    {new Date(createdAt).toLocaleString()} •{' '}
                    {actorEmail || actorUsername || actorUserId || 'onbekend'} • {action} •{' '}
                    {resourceType}:{resourceId}
                  </Typography>
                </Paper>
              )
            })}
          </Stack>
        )}
      </Paper>

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }} justifyContent="space-between" sx={{ mb: 1 }}>
          <Typography sx={{ fontWeight: 900 }}>
            Frontend errors ({PAGE_SIZE} per pagina{frontendErrTotal != null ? `, totaal ${frontendErrTotal}` : ''})
          </Typography>
          <Stack direction="row" spacing={1}>
            <Button variant="outlined" startIcon={<DownloadIcon />} disabled={busy} onClick={() => void downloadFrontendErrorsJson()}>
              Download JSON
            </Button>
            <Button variant="outlined" color="error" disabled={busy || !frontendErrors?.length} onClick={() => void clearFrontendErrors()}>
              Clear
            </Button>
          </Stack>
        </Stack>
        <Stack direction="row" spacing={1} justifyContent="flex-end" sx={{ mb: 1 }}>
          <Button variant="outlined" disabled={busy || frontendErrPage === 0} onClick={() => setFrontendErrPage((p) => Math.max(0, p - 1))}>
            Vorige
          </Button>
          <Button
            variant="outlined"
            disabled={busy || (frontendErrTotal != null ? (frontendErrPage + 1) * PAGE_SIZE >= frontendErrTotal : false)}
            onClick={() => setFrontendErrPage((p) => p + 1)}
          >
            Volgende
          </Button>
          <Typography variant="body2" color="text.secondary" sx={{ alignSelf: 'center' }}>
            Pagina {frontendErrPage + 1}
          </Typography>
        </Stack>
        {!frontendErrors && <Alert severity="info">Laden…</Alert>}
        {frontendErrors && frontendErrors.length === 0 && <Alert severity="info">Geen frontend errors.</Alert>}
        {frontendErrors && frontendErrors.length > 0 && (
          <Stack spacing={1}>
            {frontendErrors.slice(0, 30).map((e) => {
              const eId = typeof e.id === 'number' ? e.id : 0
              const createdAt = typeof e.createdAt === 'number' ? e.createdAt : typeof e.createdAt === 'string' ? Number(e.createdAt) : Date.now()
              const level = typeof e.level === 'string' ? e.level : 'error'
              const source = typeof e.source === 'string' ? e.source : 'unknown'
              const message = typeof e.message === 'string' ? e.message : String(e.message ?? '')
              const open = frontendOpenId === eId
              return (
                <Paper
                  key={eId}
                  variant="outlined"
                  sx={{ p: 1.25, cursor: 'pointer' }}
                  onClick={() => setFrontendOpenId((cur) => (cur === eId ? null : eId))}
                >
                  <Typography sx={{ fontWeight: 800 }}>
                    {new Date(createdAt).toLocaleString()} • {level} • {source} • {message}
                  </Typography>
                  {open && (
                    <Box sx={{ mt: 1 }}>
                      {typeof e.stack === 'string' && e.stack && (
                        <Paper variant="outlined" sx={{ p: 1, bgcolor: 'background.default' }}>
                          <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                            {e.stack.slice(0, 3000)}
                          </Typography>
                        </Paper>
                      )}
                      {typeof e.metaJson === 'string' && e.metaJson && e.metaJson !== '{}' && (
                        <Paper variant="outlined" sx={{ p: 1, mt: 1, bgcolor: 'background.default' }}>
                          <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                            {e.metaJson.slice(0, 3000)}
                          </Typography>
                        </Paper>
                      )}
                    </Box>
                  )}
                </Paper>
              )
            })}
          </Stack>
        )}
      </Paper>

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }} justifyContent="space-between" sx={{ mb: 1 }}>
          <Typography sx={{ fontWeight: 900 }}>
            Backend errors ({PAGE_SIZE} per pagina{backendErrTotal != null ? `, totaal ${backendErrTotal}` : ''})
          </Typography>
          <Stack direction="row" spacing={1}>
            <Button variant="outlined" startIcon={<DownloadIcon />} disabled={busy} onClick={() => void downloadBackendErrors('ndjson')}>
              Download NDJSON
            </Button>
            <Button variant="outlined" startIcon={<DownloadIcon />} disabled={busy} onClick={() => void downloadBackendErrors('json')}>
              Download JSON
            </Button>
          </Stack>
        </Stack>
        <Stack direction="row" spacing={1} justifyContent="flex-end" sx={{ mb: 1 }}>
          <Button variant="outlined" disabled={busy || backendErrPage === 0} onClick={() => setBackendErrPage((p) => Math.max(0, p - 1))}>
            Vorige
          </Button>
          <Button
            variant="outlined"
            disabled={busy || (backendErrTotal != null ? (backendErrPage + 1) * PAGE_SIZE >= backendErrTotal : false)}
            onClick={() => setBackendErrPage((p) => p + 1)}
          >
            Volgende
          </Button>
          <Typography variant="body2" color="text.secondary" sx={{ alignSelf: 'center' }}>
            Pagina {backendErrPage + 1}
          </Typography>
        </Stack>
        {!backendErrors && <Alert severity="info">Laden…</Alert>}
        {backendErrors && backendErrors.length === 0 && <Alert severity="info">Geen backend errors.</Alert>}
        {backendErrors && backendErrors.length > 0 && (
          <Stack spacing={1}>
            {backendErrors.slice(0, 20).map((e, idx: number) => {
              const open = backendOpenIdx === idx
              const ts = typeof e.ts === 'number' ? e.ts : typeof e.ts === 'string' ? Number(e.ts) : Date.now()
              const type = typeof e.type === 'string' ? e.type : 'error'
              const message = typeof e.message === 'string' ? e.message : ''
              const when = new Date(ts).toLocaleString()
              const headline = `${when} • ${type} • ${message}`.trim()
              return (
                <Paper
                  key={idx}
                  variant="outlined"
                  sx={{ p: 1.25, cursor: 'pointer' }}
                  onClick={() => setBackendOpenIdx((cur) => (cur === idx ? null : idx))}
                >
                  <Typography sx={{ fontWeight: 800 }}>{headline}</Typography>
                  {open && (
                    <Box sx={{ mt: 1 }}>
                      {typeof e.stack === 'string' && e.stack && (
                        <Paper variant="outlined" sx={{ p: 1, bgcolor: 'background.default' }}>
                          <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                            {e.stack.slice(0, 3000)}
                          </Typography>
                        </Paper>
                      )}
                      <Paper variant="outlined" sx={{ p: 1, mt: 1, bgcolor: 'background.default' }}>
                        <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                          {JSON.stringify(e, null, 2).slice(0, 3000)}
                        </Typography>
                      </Paper>
                    </Box>
                  )}
                </Paper>
              )
            })}
          </Stack>
        )}
      </Paper>

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography sx={{ fontWeight: 900, mb: 1 }}>Groepen</Typography>
        <Alert severity="info">Groepen zijn verwijderd uit de applicatie.</Alert>
      </Paper>

      {error && <Alert severity="error">{error}</Alert>}

      <Box sx={{ display: 'grid', gap: 1 }}>
        {sorted.map((u) => (
          <Paper key={u.id} variant="outlined" sx={{ p: 1.5 }}>
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }}>
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Typography sx={{ fontWeight: 900 }} noWrap>
                  {u.firstName} {u.lastName} • @{u.username}
                </Typography>
                <Typography variant="body2" color="text.secondary" noWrap>
                  {u.email} • verified: {String(u.emailVerified)} • admin: {String(u.isAdmin)}
                </Typography>
              </Box>
              <Stack direction="row" spacing={1} justifyContent="flex-end">
                <Button
                  variant="outlined"
                  startIcon={<EditOutlinedIcon />}
                  onClick={() => {
                    setDraft({ ...u, newPassword: '' })
                    setOpen(true)
                  }}
                >
                  Bewerk
                </Button>
                <Button
                  color="error"
                  variant="outlined"
                  startIcon={<DeleteOutlineIcon />}
                  onClick={() => void remove(u.id)}
                >
                  Delete
                </Button>
              </Stack>
            </Stack>
          </Paper>
        ))}
        {users && users.length === 0 && <Alert severity="info">Geen users.</Alert>}
        {!users && <Alert severity="info">Laden…</Alert>}
      </Box>

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm" fullScreen={fullScreenDialog}>
        <DialogTitle>User bewerken</DialogTitle>
        <DialogContent sx={{ display: 'grid', gap: 2, pt: 2 }}>
          <TextField
            label="Email"
            value={draft?.email ?? ''}
            onChange={(e) => setDraft((d) => (d ? { ...d, email: e.target.value } : d))}
          />
          <TextField
            label="Username"
            value={draft?.username ?? ''}
            onChange={(e) => setDraft((d) => (d ? { ...d, username: e.target.value } : d))}
          />
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              label="Voornaam"
              value={draft?.firstName ?? ''}
              onChange={(e) => setDraft((d) => (d ? { ...d, firstName: e.target.value } : d))}
              fullWidth
            />
            <TextField
              label="Achternaam"
              value={draft?.lastName ?? ''}
              onChange={(e) => setDraft((d) => (d ? { ...d, lastName: e.target.value } : d))}
              fullWidth
            />
          </Stack>
          <FormControlLabel
            control={
              <Checkbox
                checked={!!draft?.emailVerified}
                onChange={(e) => setDraft((d) => (d ? { ...d, emailVerified: e.target.checked } : d))}
              />
            }
            label="Email verified"
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={!!draft?.isAdmin}
                onChange={(e) => setDraft((d) => (d ? { ...d, isAdmin: e.target.checked } : d))}
              />
            }
            label="Is admin"
          />
          {/* Groepen zijn verwijderd */}
          <TextField
            label="Nieuw wachtwoord (optioneel)"
            type="password"
            value={draft?.newPassword ?? ''}
            onChange={(e) => setDraft((d) => (d ? { ...d, newPassword: e.target.value } : d))}
            helperText="Leeg laten = niet wijzigen"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Annuleer</Button>
          <Button variant="contained" onClick={() => void save()} disabled={busy}>
            Opslaan
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="sm" fullScreen={fullScreenDialog}>
        <DialogTitle>Nieuwe gebruiker</DialogTitle>
        <DialogContent sx={{ display: 'grid', gap: 2, pt: 2 }}>
          <TextField
            label="Email"
            value={create.email}
            onChange={(e) => setCreate((c) => ({ ...c, email: e.target.value }))}
          />
          <TextField
            label="Username"
            value={create.username}
            onChange={(e) => setCreate((c) => ({ ...c, username: e.target.value }))}
          />
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              label="Voornaam"
              value={create.firstName}
              onChange={(e) => setCreate((c) => ({ ...c, firstName: e.target.value }))}
              fullWidth
            />
            <TextField
              label="Achternaam"
              value={create.lastName}
              onChange={(e) => setCreate((c) => ({ ...c, lastName: e.target.value }))}
              fullWidth
            />
          </Stack>
          <TextField
            label="Wachtwoord"
            type="password"
            value={create.password}
            onChange={(e) => setCreate((c) => ({ ...c, password: e.target.value }))}
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={create.emailVerified}
                onChange={(e) => setCreate((c) => ({ ...c, emailVerified: e.target.checked }))}
              />
            }
            label="Email verified (uitzetten = verify mail sturen)"
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={create.isAdmin}
                onChange={(e) => setCreate((c) => ({ ...c, isAdmin: e.target.checked }))}
              />
            }
            label="Is admin"
          />
          {/* Groepen zijn verwijderd */}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Annuleer</Button>
          <Button
            variant="contained"
            onClick={() => void createUser()}
            disabled={
              busy ||
              !create.email ||
              !create.username ||
              !create.firstName ||
              !create.lastName ||
              !create.password
            }
          >
            Aanmaken
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}


