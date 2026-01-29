import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline'
import DownloadIcon from '@mui/icons-material/Download'
import NoteAddIcon from '@mui/icons-material/NoteAdd'
import PreviewIcon from '@mui/icons-material/Preview'
import SaveIcon from '@mui/icons-material/Save'
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Divider,
  IconButton,
  List,
  ListItemButton,
  ListItemSecondaryAction,
  ListItemText,
  MenuItem,
  Paper,
  Stack,
  Switch,
  TextField,
  FormControlLabel,
  Typography,
} from '@mui/material'
import JSZip from 'jszip'
import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { FilePreviewDialog } from '../components/FilePreviewDialog'
import { RichTextEditor } from '../components/RichTextEditor'
import { NotePreviewDialog } from '../components/NotePreviewDialog'
import type { StoredFile } from '../db/db'
import { fetchFileBlob, formatBytes } from '../utils/files'
import { apiFetch, useApiToken } from '../api/client'
import { useWorkspace } from '../hooks/useWorkspace'
import { useWorkspaceEvents } from '../hooks/useWorkspaceEvents'
import { getWorkspacePermissions } from '../utils/permissions'

function stripHtmlToText(input: string): string {
  // Intentionally avoid DOMParser/innerHTML to prevent treating untrusted strings as HTML.
  // We only remove HTML tags and normalize whitespace; we do not touch HTML entities at all.
  return String(input ?? '')
    .replace(/\r\n/g, '\n')
    .replace(/<\s*br\s*\/?\s*>/gi, '\n')
    .replace(/<\/\s*p\s*>/gi, '\n')
    .replace(/<\/\s*div\s*>/gi, '\n')
    .replace(/<[^>]*>/g, '')
    .replace(/\s+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

type ServerNote = {
  id: string
  subject: string
  body: string
  createdAt: number
  updatedAt: number
}

type ServerPlanningItem = {
  id: string
  date: string
  start: string
  end: string
  title: string
}

type ServerFile = {
  id: string
  userId: string
  workspaceId: string | null
  name: string
  type: string
  size: number
  groupKey: string
  version: number
  createdAt: number
  updatedAt: number
}

type ServerFileMeta = {
  groupKey: string
  folder: string
  labelsJson: string
  createdAt: number
  updatedAt: number
}

type DraftNote = {
  id?: string
  subject: string
  body: string
  attachmentGroupKeys: string[]
  updatedAt?: number
}

type FileGroup = {
  groupKey: string
  name: string
  type: string
  size: number
  latest: ServerFile
  folder: string
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

function safeFilename(name: string, fallback: string) {
  const trimmed = name.trim()
  if (!trimmed) return fallback
  return trimmed
    // eslint-disable-next-line no-control-regex
    .replace(/[<>:"/\\|?*\u0000-\u001F]/g, '_')
    .replace(/\s+/g, ' ')
    .slice(0, 80)
}

function toStoredFile(file: ServerFile): StoredFile {
  return {
    name: file.name,
    type: file.type,
    size: file.size,
    data: new Blob(),
    groupKey: file.groupKey,
    version: file.version,
    createdAt: file.createdAt,
    remoteId: file.id,
  }
}

export function NotesPage() {
  const token = useApiToken()
  const { currentWorkspace } = useWorkspace()
  const permissions = getWorkspacePermissions(currentWorkspace?.role)
  const canEdit = permissions.canEdit
  const [params] = useSearchParams()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [draft, setDraft] = useState<DraftNote>(() => ({
    subject: '',
    body: '',
    attachmentGroupKeys: [],
  }))
  const [notes, setNotes] = useState<ServerNote[]>([])
  const [files, setFiles] = useState<ServerFile[]>([])
  const [metas, setMetas] = useState<ServerFileMeta[]>([])
  const [planning, setPlanning] = useState<ServerPlanningItem[]>([])
  const [noteLinks, setNoteLinks] = useState<{ planningId: string; fileKeys: string[] }>({ planningId: '', fileKeys: [] })
  const [status, setStatus] = useState<string | null>(null)
  const [preview, setPreview] = useState<StoredFile | null>(null)
  const [notePreviewOpen, setNotePreviewOpen] = useState(false)
  const [htmlMode, setHtmlMode] = useState(false)
  const [refreshTick, setRefreshTick] = useState(0)

  useWorkspaceEvents((evt) => {
    if (['notes', 'files', 'planning', 'file_meta', 'links'].includes(evt.type)) {
      setRefreshTick((v) => v + 1)
    }
  })

  // Load notes for current workspace
  useEffect(() => {
    if (!token || !currentWorkspace?.id) return
    const workspaceId = String(currentWorkspace.id)
    const url = `/notes?workspaceId=${encodeURIComponent(workspaceId)}`
    let cancelled = false
    async function sync() {
      try {
        const result = await apiFetch(url, { token: token || undefined })
        if (cancelled) return
        const remoteNotes = (result.notes || []) as ServerNote[]
        remoteNotes.sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0))
        setNotes(remoteNotes)
      } catch (e) {
        if (import.meta.env.DEV) {
          console.error('Failed to load notes:', e)
        }
      }
    }
    void sync()
    const interval = setInterval(() => {
      if (!cancelled) void sync()
    }, 30000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [token, currentWorkspace?.id, refreshTick])

  // Load files for current workspace
  useEffect(() => {
    if (!token || !currentWorkspace?.id) return
    const workspaceId = String(currentWorkspace.id)
    const url = `/files?workspaceId=${encodeURIComponent(workspaceId)}`
    let cancelled = false
    async function sync() {
      try {
        const result = await apiFetch(url, { token: token || undefined })
        if (cancelled) return
        const remoteFiles = (result.files || []) as ServerFile[]
        remoteFiles.sort((a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0))
        setFiles(remoteFiles)
      } catch (e) {
        if (import.meta.env.DEV) {
          console.error('Failed to load files:', e)
        }
      }
    }
    void sync()
    return () => {
      cancelled = true
    }
  }, [token, currentWorkspace?.id, refreshTick])

  // Load file meta for current workspace
  useEffect(() => {
    if (!token || !currentWorkspace?.id) return
    const workspaceId = String(currentWorkspace.id)
    const url = `/file-meta?workspaceId=${encodeURIComponent(workspaceId)}`
    let cancelled = false
    async function sync() {
      try {
        const result = await apiFetch(url, { token: token || undefined })
        if (cancelled) return
        const remoteMeta = (result.items || []) as ServerFileMeta[]
        setMetas(remoteMeta)
      } catch (e) {
        if (import.meta.env.DEV) {
          console.error('Failed to load file meta:', e)
        }
      }
    }
    void sync()
    return () => {
      cancelled = true
    }
  }, [token, currentWorkspace?.id, refreshTick])

  // Load planning items for linking
  useEffect(() => {
    if (!token || !currentWorkspace?.id) return
    const workspaceId = String(currentWorkspace.id)
    const url = `/planning?workspaceId=${encodeURIComponent(workspaceId)}`
    let cancelled = false
    async function sync() {
      try {
        const result = await apiFetch(url, { token: token || undefined })
        if (cancelled) return
        const items = (result.items || []) as ServerPlanningItem[]
        items.sort((a, b) => (a.date + a.start).localeCompare(b.date + b.start))
        setPlanning(items)
      } catch (e) {
        if (import.meta.env.DEV) {
          console.error('Failed to load planning items:', e)
        }
      }
    }
    void sync()
    return () => {
      cancelled = true
    }
  }, [token, currentWorkspace?.id, refreshTick])

  // Load links for selected note
  useEffect(() => {
    if (!token || !currentWorkspace?.id || !selectedId) {
      setNoteLinks({ planningId: '', fileKeys: [] })
      return
    }
    const workspaceId = String(currentWorkspace.id)
    const url = `/links?workspaceId=${encodeURIComponent(workspaceId)}&fromType=note&fromId=${encodeURIComponent(selectedId)}`
    let cancelled = false
    async function sync() {
      try {
        const result = await apiFetch(url, { token: token || undefined })
        if (cancelled) return
        const items = (result.items || []) as Array<{ toType: 'fileGroup' | 'note' | 'planning'; toKey: string }>
        const planningId = items.find((l) => l.toType === 'planning')?.toKey ?? ''
        const fileKeys = items.filter((l) => l.toType === 'fileGroup').map((l) => l.toKey)
        setNoteLinks({ planningId, fileKeys })
        setDraft((d) => ({ ...d, attachmentGroupKeys: fileKeys }))
      } catch (e) {
        if (import.meta.env.DEV) {
          console.error('Failed to load links:', e)
        }
      }
    }
    void sync()
    return () => {
      cancelled = true
    }
  }, [token, currentWorkspace?.id, selectedId, refreshTick])

  useEffect(() => {
    const qId = params.get('noteId')
    if (qId) setSelectedId(qId)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!notes) return
    if (selectedId == null) return
    const found = notes.find((n) => n.id === selectedId)
    if (found) {
      setDraft({
        id: found.id,
        subject: found.subject,
        body: found.body,
        attachmentGroupKeys: noteLinks.fileKeys,
        updatedAt: found.updatedAt,
      })
    }
  }, [notes, selectedId, noteLinks.fileKeys])

  const fileGroups = useMemo<FileGroup[]>(() => {
    const map = new Map<string, { groupKey: string; name: string; type: string; size: number; latest: ServerFile }>()
    for (const f of files ?? []) {
      const cur = map.get(f.groupKey)
      if (!cur || (f.createdAt ?? 0) > cur.latest.createdAt) {
        map.set(f.groupKey, { groupKey: f.groupKey, name: f.name, type: f.type, size: f.size, latest: f })
      }
    }
    const metaByKey = new Map<string, ServerFileMeta>()
    for (const m of metas ?? []) metaByKey.set(m.groupKey, m)
    return Array.from(map.values()).map((g) => ({
      ...g,
      folder: metaByKey.get(g.groupKey)?.folder || '',
    }))
  }, [files, metas])

  const selectedFiles = useMemo(() => {
    const byKey = new Map(fileGroups.map((g) => [g.groupKey, g] as const))
    return (draft.attachmentGroupKeys ?? [])
      .map((k) => byKey.get(k))
      .filter((g): g is FileGroup => Boolean(g))
  }, [fileGroups, draft.attachmentGroupKeys])

  function newNote() {
    if (!canEdit) return
    setSelectedId(null)
    setDraft({
      subject: '',
      body: '',
      attachmentGroupKeys: [],
    })
    setStatus(null)
  }

  async function saveLinks(next: { planningId: string; fileKeys: string[] }, noteId: string) {
    if (!canEdit) return
    if (!token || !currentWorkspace?.id) {
      setNoteLinks(next)
      return
    }
    const workspaceId = String(currentWorkspace.id)
    const links = [
      ...(next.planningId ? [{ toType: 'planning' as const, toKey: next.planningId }] : []),
      ...next.fileKeys.map((k) => ({ toType: 'fileGroup' as const, toKey: k })),
    ]
    try {
      await apiFetch('/links', {
        method: 'POST',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          workspaceId,
          fromType: 'note',
          fromId: noteId,
          links,
        }),
      })
      setNoteLinks(next)
    } catch (e) {
      if (import.meta.env.DEV) {
        console.error('Failed to save links:', e)
      }
    }
  }

  async function save() {
    if (!canEdit) return
    setStatus(null)
    if (!token || !currentWorkspace?.id) return
    try {
      const result = await apiFetch(`/notes?workspaceId=${encodeURIComponent(currentWorkspace.id)}`, {
        method: 'POST',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          id: draft.id,
          subject: draft.subject,
          body: draft.body,
          workspaceId: currentWorkspace.id,
        }),
      })
      const note = result.note as ServerNote
      setNotes((prev) => {
        const idx = prev.findIndex((n) => n.id === note.id)
        if (idx >= 0) {
          const next = prev.slice()
          next[idx] = note
          return next
        }
        return [note, ...prev]
      })
      setSelectedId(note.id)
      setDraft((d) => ({ ...d, id: note.id }))
      await saveLinks({ planningId: noteLinks.planningId, fileKeys: draft.attachmentGroupKeys }, note.id)
      setStatus('Opgeslagen.')
    } catch (e) {
      if (import.meta.env.DEV) {
        console.error('Failed to save note:', e)
      }
    }
  }

  async function remove() {
    if (!canEdit) return
    if (!draft.id) {
      newNote()
      return
    }
    if (!token) return
    try {
      await apiFetch(`/notes/${draft.id}`, { method: 'DELETE', token: token || undefined })
      setNotes((prev) => prev.filter((n) => n.id !== draft.id))
      newNote()
    } catch (e) {
      if (import.meta.env.DEV) {
        console.error('Failed to delete note:', e)
      }
    }
  }

  async function downloadRemote(file: ServerFile) {
    if (!token) return
    try {
      const blob = await fetchFileBlob(file.id, token)
      downloadBlob(blob, file.name)
    } catch {
      // ignore
    }
  }

  function exportTxt() {
    const fallback = `note-${new Date().toISOString().slice(0, 10)}.txt`
    const filename = safeFilename(draft.subject, fallback)
    const attachmentLines =
      selectedFiles.length === 0
        ? '(geen)'
        : selectedFiles.map((f) => `- ${f.name}`).join('\n')

    const html = draft.body || ''
    const txt = stripHtmlToText(html)
    const content = `Onderwerp: ${draft.subject || '(geen)'}\n\n${txt || ''}\n\nBijlages:\n${attachmentLines}\n`
    downloadBlob(new Blob([content], { type: 'text/plain;charset=utf-8' }), filename)
  }

  async function exportZip() {
    const zip = new JSZip()
    const base = safeFilename(draft.subject, 'note')

    const attachmentLines =
      selectedFiles.length === 0
        ? '(geen)'
        : selectedFiles.map((f) => `- ${f.name}`).join('\n')
    const html = draft.body || ''
    const txt = stripHtmlToText(html)
    const content = `Onderwerp: ${draft.subject || '(geen)'}\n\n${txt || ''}\n\nBijlages:\n${attachmentLines}\n`
    zip.file(`${base}.txt`, content)

    for (const g of selectedFiles) {
      const f = g.latest
      if (!token) continue
      try {
        const blob = await fetchFileBlob(f.id, token)
        zip.file(f.name, blob)
      } catch {
        // ignore missing files
      }
    }

    const blob = await zip.generateAsync({ type: 'blob' })
    downloadBlob(blob, `${base}.zip`)
  }

  return (
    <Box sx={{ display: 'grid', gap: { xs: 1.5, sm: 2 } }}>
      <Typography variant="h5" sx={{ fontWeight: 800, fontSize: { xs: '1.125rem', sm: '1.25rem' } }}>
        Notities / mail
      </Typography>

      {!token && (
        <Alert severity="info">
          Login vereist om notities te laden en op te slaan voor de werkgroep.
        </Alert>
      )}

      <Stack direction="column" spacing={{ xs: 1.5, sm: 2 }} sx={{ '@media (min-width:900px)': { flexDirection: 'row', alignItems: 'stretch' } }}>
        <Paper sx={{ width: '100%', overflow: 'hidden', '@media (min-width:900px)': { width: 360 } }}>
          <Box sx={{ p: { xs: 1.5, sm: 2 } }}>
            <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
              <Typography sx={{ fontWeight: 800 }}>Opgeslagen</Typography>
              <Button startIcon={<NoteAddIcon />} onClick={newNote} disabled={!canEdit}>
                Nieuw
              </Button>
            </Stack>
            <Typography variant="body2" color="text.secondary">
              Klik een item om te bewerken.
            </Typography>
          </Box>
          <Divider />
          <List dense disablePadding>
            {notes?.map((n) => (
              <ListItemButton
                key={n.id}
                selected={selectedId === n.id}
                onClick={() => n.id != null && setSelectedId(n.id)}
              >
                <ListItemText
                  primary={n.subject?.trim() ? n.subject : '(zonder onderwerp)'}
                  secondary={new Date(n.updatedAt).toLocaleString()}
                />
              </ListItemButton>
            ))}
            {notes && notes.length === 0 && (
              <Box sx={{ p: 2 }}>
                <Alert severity="info">Nog geen notities.</Alert>
              </Box>
            )}
          </List>
        </Paper>

        <Paper sx={{ flex: 1, p: { xs: 1.5, sm: 2 } }}>
          <Stack spacing={{ xs: 1.5, sm: 2 }}>
            <Stack
              direction="column"
              spacing={{ xs: 1, sm: 1.5 }}
              sx={{ '@media (min-width:600px)': { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' } }}
            >
              <Typography sx={{ fontWeight: 800 }}>
                {draft.id ? 'Bewerken' : 'Nieuw'}
              </Typography>
              <Stack
                direction={{ xs: 'column', sm: 'row' }}
                spacing={1}
                justifyContent="flex-end"
                alignItems={{ xs: 'stretch', sm: 'center' }}
              >
                <Button
                  variant="outlined"
                  startIcon={<PreviewIcon />}
                  onClick={() => setNotePreviewOpen(true)}
                >
                  Preview
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={exportTxt}
                >
                  Export .txt
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={() => void exportZip()}
                >
                  Export .zip
                </Button>
              </Stack>
            </Stack>

            <TextField
              label="Onderwerp"
              value={draft.subject}
              onChange={(e) => setDraft((d) => ({ ...d, subject: e.target.value }))}
              disabled={!canEdit}
            />

            <Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 800, mb: 0.75 }}>
                Tekst
              </Typography>
              <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={htmlMode}
                      onChange={(e) => setHtmlMode(e.target.checked)}
                      disabled={!canEdit}
                    />
                  }
                  label="HTML mode"
                />
                <Typography variant="caption" color="text.secondary">
                  Preview rendert HTML (dus tags worden zichtbaar als opmaak).
                </Typography>
              </Stack>
              {htmlMode ? (
                <TextField
                  label="HTML"
                  value={draft.body}
                  onChange={(e) => setDraft((d) => ({ ...d, body: e.target.value }))}
                  multiline
                  minRows={10}
                  disabled={!canEdit}
                />
              ) : (
                <RichTextEditor value={draft.body} onChange={(html) => setDraft((d) => ({ ...d, body: html }))} />
              )}
            </Box>

            <TextField
              select
              label="Link naar planning (optioneel)"
              value={noteLinks.planningId}
              onChange={async (e) => {
                const val = e.target.value as string
                if (draft.id) {
                  await saveLinks({ planningId: val, fileKeys: draft.attachmentGroupKeys }, draft.id)
                }
                setNoteLinks((prev) => ({ ...prev, planningId: val }))
              }}
              disabled={!canEdit}
            >
              <MenuItem value="">(geen)</MenuItem>
              {(planning ?? []).map((p) => (
                <MenuItem key={p.id} value={String(p.id)}>
                  {p.date} {p.start}-{p.end} • {p.title}
                </MenuItem>
              ))}
            </TextField>

            <Autocomplete<FileGroup, true, false, false>
              multiple
              options={fileGroups}
              value={selectedFiles}
              isOptionEqualToValue={(o, v) => o.groupKey === v.groupKey}
              getOptionLabel={(o) => `${o.name}${o.folder ? ` • ${o.folder}` : ''}`}
              onChange={(_e, newValue) => {
                const keys = newValue.map((f) => f.groupKey)
                setDraft((d) => ({ ...d, attachmentGroupKeys: keys }))
                if (draft.id) {
                  void saveLinks({ planningId: noteLinks.planningId, fileKeys: keys }, draft.id)
                }
              }}
              disabled={!canEdit}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Bijlages (kies uit Bestanden)"
                  placeholder={fileGroups.length > 0 ? 'Selecteer...' : 'Geen bestanden geüpload'}
                />
              )}
            />

            {selectedFiles.length > 0 && (
              <Paper variant="outlined" sx={{ p: { xs: 0.75, sm: 1 } }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 800, mb: 1 }}>
                  Geselecteerde bijlages
                </Typography>
                <List dense disablePadding>
                  {selectedFiles.map((g) => (
                    <ListItemButton key={g.groupKey} onClick={() => setPreview(toStoredFile(g.latest))}>
                      <ListItemText
                        primary={g.name}
                        secondary={`${formatBytes(g.size)} • ${g.type || 'onbekend'}`}
                      />
                      <ListItemSecondaryAction>
                        <IconButton aria-label="Preview" edge="end" onClick={() => setPreview(toStoredFile(g.latest))}>
                          <PreviewIcon />
                        </IconButton>
                        <IconButton
                          aria-label="Download"
                          edge="end"
                          onClick={() => void downloadRemote(g.latest)}
                        >
                          <DownloadIcon />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItemButton>
                  ))}
                </List>
              </Paper>
            )}

            {files && files.length === 0 && (
              <Alert severity="info">
                Upload eerst bestanden via de tab <b>Bestanden</b> om ze als bijlage te kunnen kiezen.
              </Alert>
            )}

            {status && <Alert severity="success">{status}</Alert>}

            <Stack direction="row" spacing={1} justifyContent="flex-end">
              <Button
                color="error"
                variant="outlined"
                startIcon={<DeleteOutlineIcon />}
                onClick={() => void remove()}
                disabled={!canEdit}
              >
                Verwijder
              </Button>
              <Button variant="contained" startIcon={<SaveIcon />} onClick={() => void save()} disabled={!canEdit}>
                Opslaan
              </Button>
            </Stack>
          </Stack>
        </Paper>
      </Stack>

      <FilePreviewDialog open={!!preview} file={preview} onClose={() => setPreview(null)} />
      <NotePreviewDialog
        open={notePreviewOpen}
        note={draft}
        files={selectedFiles.map((g) => toStoredFile(g.latest))}
        onClose={() => setNotePreviewOpen(false)}
      />
    </Box>
  )
}


