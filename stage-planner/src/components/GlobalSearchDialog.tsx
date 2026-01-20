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

type Result =
  | { kind: 'planning'; id: string; primary: string; secondary: string; date: string }
  | { kind: 'note'; id: string; primary: string; secondary: string }
  | { kind: 'file'; groupKey: string; primary: string; secondary: string }

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
  const [results, setResults] = useState<Result[] | null>(null)

  const qq = useMemo(() => q.trim().toLowerCase(), [q])

  useEffect(() => {
    if (!open) return
    setQ('')
    setResults(null)
  }, [open])

  useEffect(() => {
    if (!open) return
    let cancelled = false
    const t = setTimeout(async () => {
      if (!qq) {
        setResults([])
        return
      }
      if (!token || !currentWorkspace?.id) {
        setResults([])
        return
      }
      const out: Result[] = []
      const workspaceId = String(currentWorkspace.id)
      const [planningRes, notesRes, filesRes, metaRes] = await Promise.all([
        apiFetch(`/planning?workspaceId=${encodeURIComponent(workspaceId)}`, { token: token || undefined }),
        apiFetch(`/notes?workspaceId=${encodeURIComponent(workspaceId)}`, { token: token || undefined }),
        apiFetch(`/files?workspaceId=${encodeURIComponent(workspaceId)}`, { token: token || undefined }),
        apiFetch(`/file-meta?workspaceId=${encodeURIComponent(workspaceId)}`, { token: token || undefined }),
      ])
      const planning = (planningRes.items || []) as Array<{
        id: string
        date: string
        start: string
        end: string
        title: string
        notes?: string | null
        tagsJson?: string
      }>
      for (const it of planning) {
        const tags = (() => {
          try {
            return (JSON.parse(it.tagsJson || '[]') as string[]).join(' ')
          } catch {
            return ''
          }
        })()
        const hay = `${it.title} ${it.notes ?? ''} ${it.date} ${it.start}-${it.end} ${tags}`.toLowerCase()
        if (hay.includes(qq) && it.id) {
          out.push({
            kind: 'planning',
            id: it.id,
            date: it.date,
            primary: it.title,
            secondary: `${it.date} ${it.start}-${it.end}`,
          })
        }
      }
      const notes = (notesRes.notes || []) as Array<{ id: string; subject: string; body: string; updatedAt: number }>
      for (const n of notes) {
        const bodyTxt = stripHtml(n.body || '')
        const hay = `${n.subject} ${bodyTxt}`.toLowerCase()
        if (hay.includes(qq) && n.id) {
          out.push({
            kind: 'note',
            id: n.id,
            primary: n.subject?.trim() ? n.subject : '(zonder onderwerp)',
            secondary: new Date(n.updatedAt).toLocaleString(),
          })
        }
      }
      // files by group
      const files = (filesRes.files || []) as Array<{ groupKey: string; name: string; type: string }>
      const metas = (metaRes.items || []) as Array<{ groupKey: string; folder: string; labelsJson?: string }>
      const metaByKey = new Map(metas.map((m) => [m.groupKey, m] as const))
      const seen = new Set<string>()
      for (const f of files) {
        if (seen.has(f.groupKey)) continue
        seen.add(f.groupKey)
        const meta = metaByKey.get(f.groupKey)
        const labels = meta ? (JSON.parse(meta.labelsJson || '[]') as string[]).join(' ') : ''
        const hay = `${f.name} ${f.type} ${meta?.folder || ''} ${labels}`.toLowerCase()
        if (hay.includes(qq)) {
          out.push({
            kind: 'file',
            groupKey: f.groupKey,
            primary: f.name,
            secondary: meta?.folder ? `Folder: ${meta.folder}` : f.type,
          })
        }
      }

      if (!cancelled) setResults(out.slice(0, 30))
    }, 250)
    return () => {
      cancelled = true
      clearTimeout(t)
    }
  }, [open, qq, token, currentWorkspace?.id, refreshTick])

  function go(r: Result) {
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

        <Box sx={{ mt: { xs: 1.5, sm: 2 } }}>
          {results == null ? (
            <Alert severity="info">Typ om te zoeken…</Alert>
          ) : results.length === 0 ? (
            <Alert severity="info">Geen resultaten.</Alert>
          ) : (
            <List dense disablePadding>
              {results.map((r, idx) => (
                <ListItemButton key={idx} onClick={() => go(r)}>
                  <ListItemText primary={r.primary} secondary={`${r.kind} • ${r.secondary}`} />
                </ListItemButton>
              ))}
            </List>
          )}
        </Box>
      </DialogContent>
    </Dialog>
  )
}




