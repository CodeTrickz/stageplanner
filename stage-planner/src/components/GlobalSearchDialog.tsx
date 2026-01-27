import SearchIcon from '@mui/icons-material/Search'
import {
  Alert,
  Box,
  Dialog,
  DialogContent,
  DialogTitle,
  List,
  ListItemButton,
  ListItemText,
  MenuItem,
  TextField,
  Typography,
  useMediaQuery,
  useTheme,
} from '@mui/material'
import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiFetch, useApiToken } from '../api/client'
import { useWorkspace } from '../hooks/useWorkspace'
import { useWorkspaceEvents } from '../hooks/useWorkspaceEvents'

type PlanningResult = { kind: 'planning'; id: string; primary: string; secondary: string; date: string; start: string }
type NoteResult = { kind: 'note'; id: string; primary: string; secondary: string; updatedAt: number }
type FileResult = { kind: 'file'; groupKey: string; primary: string; secondary: string; updatedAt: number }

function stripHtml(html: string) {
  try {
    return new DOMParser().parseFromString(html, 'text/html').body.textContent ?? ''
  } catch {
    return html
  }
}

export function GlobalSearchDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const nav = useNavigate()
  const { currentWorkspace } = useWorkspace()
  const theme = useTheme()
  const fullScreen = useMediaQuery(theme.breakpoints.down('sm'))
  const token = useApiToken()
  const [refreshTick, setRefreshTick] = useState(0)

  useWorkspaceEvents((evt) => {
    if (['planning', 'notes', 'files', 'file_meta'].includes(evt.type)) {
      setRefreshTick((v) => v + 1)
    }
  })
  const [q, setQ] = useState('')
  const [status, setStatus] = useState<'' | 'todo' | 'in_progress' | 'done'>('')
  const [priority, setPriority] = useState<'' | 'low' | 'medium' | 'high'>('')
  const [tag, setTag] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [sortOrder, setSortOrder] = useState<'newest' | 'oldest'>('newest')
  const [results, setResults] = useState<{
    planning: PlanningResult[]
    notes: NoteResult[]
    files: FileResult[]
  } | null>(null)

  const qq = useMemo(() => q.trim().toLowerCase(), [q])

  useEffect(() => {
    if (!open) return
    setQ('')
    setStatus('')
    setPriority('')
    setTag('')
    setDateFrom('')
    setDateTo('')
    setSortOrder('newest')
    setResults(null)
  }, [open])

  useEffect(() => {
    if (!open) return
    let cancelled = false
    const t = setTimeout(async () => {
      if (!qq && !status && !priority && !tag && !dateFrom && !dateTo) {
        setResults([])
        return
      }
      if (!token || !currentWorkspace?.id) {
        setResults([])
        return
      }
      const planningOut: PlanningResult[] = []
      const notesOut: NoteResult[] = []
      const filesOut: FileResult[] = []
      const workspaceId = String(currentWorkspace.id)
      const params = new URLSearchParams({ workspaceId })
      if (qq) params.set('q', qq)
      if (status) params.set('status', status)
      if (priority) params.set('priority', priority)
      if (tag.trim()) params.set('tag', tag.trim())
      if (dateFrom) params.set('from', dateFrom)
      if (dateTo) params.set('to', dateTo)
      try {
        const res = await apiFetch(`/search?${params.toString()}`, { token: token || undefined })

        const planning = (res.planning || []) as Array<{
          id: string
          date: string
          start: string
          end: string
          title: string
          status: string
          priority: string
          updatedAt: number
        }>
        for (const it of planning) {
          planningOut.push({
            kind: 'planning',
            id: it.id,
            date: it.date,
            start: it.start,
            primary: it.title,
            secondary: `${it.date} ${it.start}-${it.end} • ${it.status}/${it.priority}`,
          })
        }

        const notes = (res.notes || []) as Array<{ id: string; subject: string; body: string; updatedAt: number }>
        for (const n of notes) {
          const bodyTxt = stripHtml(n.body || '')
          notesOut.push({
            kind: 'note',
            id: n.id,
            primary: n.subject?.trim() ? n.subject : '(zonder onderwerp)',
            secondary: `${new Date(n.updatedAt).toLocaleString()} • ${bodyTxt.slice(0, 60)}`,
            updatedAt: n.updatedAt,
          })
        }

        const files = (res.files || []) as Array<{
          groupKey: string
          name: string
          type: string
          folder?: string | null
          updatedAt: number
        }>
        for (const f of files) {
          filesOut.push({
            kind: 'file',
            groupKey: f.groupKey,
            primary: f.name,
            secondary: f.folder ? `Folder: ${f.folder}` : f.type,
            updatedAt: f.updatedAt,
          })
        }
      } catch {
        // ignore
      }

      if (!cancelled)
        setResults({
          planning: planningOut.sort((a, b) =>
            sortOrder === 'newest'
              ? (b.date + b.start).localeCompare(a.date + a.start)
              : (a.date + a.start).localeCompare(b.date + b.start),
          ),
          notes: notesOut.sort((a, b) => (sortOrder === 'newest' ? b.updatedAt - a.updatedAt : a.updatedAt - b.updatedAt)),
          files: filesOut.sort((a, b) => (sortOrder === 'newest' ? b.updatedAt - a.updatedAt : a.updatedAt - b.updatedAt)),
        })
    }, 250)
    return () => {
      cancelled = true
      clearTimeout(t)
    }
  }, [open, qq, token, currentWorkspace?.id, refreshTick, status, priority, tag, dateFrom, dateTo, sortOrder])

  function go(r: PlanningResult | NoteResult | FileResult) {
    onClose()
    if (r.kind === 'planning') nav(`/planning?date=${encodeURIComponent(r.date)}`)
    if (r.kind === 'note') nav(`/notities?noteId=${encodeURIComponent(String(r.id))}`)
    if (r.kind === 'file') nav(`/bestanden?q=${encodeURIComponent(r.primary)}`)
  }

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm" fullScreen={fullScreen}>
      <DialogTitle sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Typography sx={{ fontWeight: 900, fontSize: { xs: '1rem', sm: '1.125rem' } }}>Zoek overal</Typography>
      </DialogTitle>
      <DialogContent dividers sx={{ p: { xs: 1.5, sm: 2 } }}>
        <TextField
          autoFocus
          fullWidth
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Zoek in planning, notities, bestanden…"
          size="small"
          InputProps={{ startAdornment: <SearchIcon sx={{ mr: { xs: 0.5, sm: 1 }, fontSize: { xs: '1rem', sm: '1.25rem' } }} /> }}
        />

        <Box sx={{ display: 'grid', gap: 1, mt: { xs: 1.5, sm: 2 } }}>
          <Box sx={{ display: 'grid', gap: 1, gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', md: 'repeat(4, 1fr)' } }}>
            <TextField
              select
              label="Status"
              size="small"
              value={status}
              onChange={(e) => setStatus(e.target.value as '' | 'todo' | 'in_progress' | 'done')}
            >
              <MenuItem value="">Alle</MenuItem>
              <MenuItem value="todo">Todo</MenuItem>
              <MenuItem value="in_progress">In progress</MenuItem>
              <MenuItem value="done">Done</MenuItem>
            </TextField>
            <TextField
              select
              label="Prioriteit"
              size="small"
              value={priority}
              onChange={(e) => setPriority(e.target.value as '' | 'low' | 'medium' | 'high')}
            >
              <MenuItem value="">Alle</MenuItem>
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
            </TextField>
            <TextField label="Tag" size="small" value={tag} onChange={(e) => setTag(e.target.value)} />
            <TextField
              label="Vanaf"
              type="date"
              size="small"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              InputLabelProps={{ shrink: true }}
            />
          </Box>
          <Box sx={{ display: 'grid', gap: 1, gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)' } }}>
            <TextField
              label="Tot"
              type="date"
              size="small"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              InputLabelProps={{ shrink: true }}
            />
            <TextField
              select
              label="Sortering"
              size="small"
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value as 'newest' | 'oldest')}
            >
              <MenuItem value="newest">Nieuwste eerst</MenuItem>
              <MenuItem value="oldest">Oudste eerst</MenuItem>
            </TextField>
          </Box>
        </Box>

        <Box sx={{ mt: { xs: 1.5, sm: 2 } }}>
          {results == null ? (
            <Alert severity="info">Typ om te zoeken…</Alert>
          ) : results.planning.length + results.notes.length + results.files.length === 0 ? (
            <Alert severity="info">Geen resultaten.</Alert>
          ) : (
            <List dense disablePadding>
              {results.planning.length > 0 && (
                <>
                  <Typography variant="overline" sx={{ px: 1, color: 'text.secondary' }}>
                    Planning
                  </Typography>
                  {results.planning.map((r, idx) => (
                    <ListItemButton key={`planning-${r.id}-${idx}`} onClick={() => go(r)}>
                      <ListItemText primary={r.primary} secondary={r.secondary} />
                    </ListItemButton>
                  ))}
                </>
              )}
              {results.notes.length > 0 && (
                <>
                  <Typography variant="overline" sx={{ px: 1, color: 'text.secondary', mt: 1 }}>
                    Notities
                  </Typography>
                  {results.notes.map((r, idx) => (
                    <ListItemButton key={`note-${r.id}-${idx}`} onClick={() => go(r)}>
                      <ListItemText primary={r.primary} secondary={r.secondary} />
                    </ListItemButton>
                  ))}
                </>
              )}
              {results.files.length > 0 && (
                <>
                  <Typography variant="overline" sx={{ px: 1, color: 'text.secondary', mt: 1 }}>
                    Bestanden
                  </Typography>
                  {results.files.map((r, idx) => (
                    <ListItemButton key={`file-${r.groupKey}-${idx}`} onClick={() => go(r)}>
                      <ListItemText primary={r.primary} secondary={r.secondary} />
                    </ListItemButton>
                  ))}
                </>
              )}
            </List>
          )}
        </Box>
      </DialogContent>
    </Dialog>
  )
}




