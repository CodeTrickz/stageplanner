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
import { useLiveQuery } from 'dexie-react-hooks'
import JSZip from 'jszip'
import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { FilePreviewDialog } from '../components/FilePreviewDialog'
import { RichTextEditor } from '../components/RichTextEditor'
import { NotePreviewDialog } from '../components/NotePreviewDialog'
import { db, type NoteDraft, type StoredFile } from '../db/db'
import { formatBytes } from '../utils/files'
import { apiFetch, useApiToken } from '../api/client'
import { useAuth } from '../auth/auth'

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

export function NotesPage() {
  const token = useApiToken()
  const { user } = useAuth()
  const ownerUserId = user?.id || null
  const [params] = useSearchParams()
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [draft, setDraft] = useState<NoteDraft>(() => ({
    ownerUserId: ownerUserId || '__local__',
    subject: '',
    body: '',
    attachmentFileIds: [],
    createdAt: Date.now(),
    updatedAt: Date.now(),
  }))
  const [status, setStatus] = useState<string | null>(null)
  const [preview, setPreview] = useState<StoredFile | null>(null)
  const [notePreviewOpen, setNotePreviewOpen] = useState(false)
  const [htmlMode, setHtmlMode] = useState(false)
  const [shareEmail, setShareEmail] = useState('')
  const [sharePerm, setSharePerm] = useState<'read' | 'write'>('read')
  const [shareStatus, setShareStatus] = useState<string | null>(null)

  const notes = useLiveQuery(async () => {
    if (!ownerUserId) return []
    const list = await db.notes.where('ownerUserId').equals(ownerUserId).toArray()
    list.sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0))
    return list
  }, [ownerUserId])

  const files = useLiveQuery(async () => {
    if (!ownerUserId) return []
    const list = await db.files.where('ownerUserId').equals(ownerUserId).toArray()
    list.sort((a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0))
    return list
  }, [ownerUserId])

  const planning = useLiveQuery(async () => {
    const list = user?.id
      ? await db.planning.where('ownerUserId').equals(user.id).toArray()
      : await db.planning.toArray()
    list.sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0))
    return list
  }, [user?.id])

  const noteLinks = useLiveQuery(async () => {
    if (!draft.id) return []
    if (!ownerUserId) return []
    const list = await db.links
      .where('[ownerUserId+fromId]')
      .equals([ownerUserId, draft.id])
      .and((l) => l.fromType === 'note')
      .toArray()
    return list
  }, [draft.id, ownerUserId])

  useEffect(() => {
    const qId = params.get('noteId')
    if (qId && /^\d+$/.test(qId)) setSelectedId(Number(qId))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!notes) return
    if (selectedId == null) return
    const found = notes.find((n) => n.id === selectedId)
    if (found) setDraft(found)
  }, [notes, selectedId])

  const selectedFiles = useMemo(() => {
    if (!files) return []
    const byId = new Map(files.map((f) => [f.id, f] as const))
    return (draft.attachmentFileIds ?? [])
      .map((id) => byId.get(id))
      .filter(Boolean) as StoredFile[]
  }, [files, draft.attachmentFileIds])

  function newNote() {
    setSelectedId(null)
    const now = Date.now()
    setDraft({
      ownerUserId,
      subject: '',
      body: '',
      attachmentFileIds: [],
      createdAt: now,
      updatedAt: now,
    })
    setStatus(null)
  }

  async function save() {
    setStatus(null)
    const now = Date.now()

    if (draft.id) {
      await db.notes.update(draft.id, {
        ownerUserId,
        subject: draft.subject,
        body: draft.body,
        attachmentFileIds: draft.attachmentFileIds ?? [],
        updatedAt: now,
      })
      // cloud sync (best effort)
      if (token) {
        const rec = await db.notes.get(draft.id)
        if (rec) {
          const remote = await apiFetch('/notes', {
            method: 'POST',
            token,
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              id: rec.remoteId,
              subject: rec.subject,
              body: rec.body,
            }),
          })
          const remoteId = remote.note?.id as string | undefined
          if (remoteId && rec.remoteId !== remoteId) await db.notes.update(draft.id, { remoteId })
        }
      }
      setStatus('Opgeslagen.')
      return
    }

    const id = await db.notes.add({
      ownerUserId,
      subject: draft.subject,
      body: draft.body,
      attachmentFileIds: draft.attachmentFileIds ?? [],
      createdAt: now,
      updatedAt: now,
    })
    setSelectedId(id)
    if (token) {
      const rec = await db.notes.get(id)
      if (rec) {
        const remote = await apiFetch('/notes', {
          method: 'POST',
          token,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            subject: rec.subject,
            body: rec.body,
          }),
        })
        const remoteId = remote.note?.id as string | undefined
        if (remoteId) await db.notes.update(id, { remoteId })
      }
    }
    setStatus('Opgeslagen.')
  }

  async function remove() {
    if (!draft.id) {
      newNote()
      return
    }
    await db.notes.delete(draft.id)
    newNote()
  }

  function exportTxt() {
    const fallback = `note-${new Date().toISOString().slice(0, 10)}.txt`
    const filename = safeFilename(draft.subject, fallback)
    const attachmentLines =
      selectedFiles.length === 0
        ? '(geen)'
        : selectedFiles.map((f) => `- ${f.name}`).join('\n')

    const html = draft.body || ''
    const txt = typeof document !== 'undefined' ? (new DOMParser().parseFromString(html, 'text/html').body.textContent ?? '') : html
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
    const txt = typeof document !== 'undefined' ? (new DOMParser().parseFromString(html, 'text/html').body.textContent ?? '') : html
    const content = `Onderwerp: ${draft.subject || '(geen)'}\n\n${txt || ''}\n\nBijlages:\n${attachmentLines}\n`
    zip.file(`${base}.txt`, content)

    for (const fileId of draft.attachmentFileIds ?? []) {
      const f = await db.files.get(fileId)
      if (!f) continue
      zip.file(f.name, f.data)
    }

    const blob = await zip.generateAsync({ type: 'blob' })
    downloadBlob(blob, `${base}.zip`)
  }

  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      <Typography variant="h5" sx={{ fontWeight: 800 }}>
        Notities / mail
      </Typography>

      {!ownerUserId && (
        <Alert severity="info">
          Login vereist: notities zijn per gebruiker privé. Andere users (ook admin) zien ze niet tenzij gedeeld (cloud).
        </Alert>
      )}

      <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems="stretch">
        <Paper sx={{ width: { xs: '100%', md: 360 }, overflow: 'hidden' }}>
          <Box sx={{ p: 2 }}>
            <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
              <Typography sx={{ fontWeight: 800 }}>Opgeslagen</Typography>
              <Button startIcon={<NoteAddIcon />} onClick={newNote}>
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

        <Paper sx={{ flex: 1, p: 2 }}>
          <Stack spacing={2}>
            <Stack
              direction={{ xs: 'column', sm: 'row' }}
              spacing={1}
              alignItems={{ xs: 'stretch', sm: 'center' }}
              justifyContent="space-between"
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
                  startIcon={<PreviewIcon />}
                  onClick={async () => {
                    if (!token) {
                      setShareStatus('Login vereist om te delen.')
                      return
                    }
                    if (!draft.id) {
                      setShareStatus('Eerst opslaan.')
                      return
                    }
                    const rec = await db.notes.get(draft.id)
                    if (!rec?.remoteId) {
                      setShareStatus('Eerst opslaan (cloud sync) om te kunnen delen.')
                      return
                    }
                    if (!shareEmail) {
                      setShareStatus('Vul email in.')
                      return
                    }
                    try {
                      await apiFetch('/shares', {
                        method: 'POST',
                        token,
                        headers: { 'content-type': 'application/json' },
                        body: JSON.stringify({
                          resourceType: 'note',
                          resourceId: rec.remoteId,
                          granteeEmail: shareEmail,
                          permission: sharePerm,
                        }),
                      })
                      setShareStatus('Gedeeld!')
                    } catch (e) {
                      setShareStatus(e instanceof Error ? e.message : 'share_failed')
                    }
                  }}
                >
                  Delen
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
                />
              ) : (
                <RichTextEditor value={draft.body} onChange={(html) => setDraft((d) => ({ ...d, body: html }))} />
              )}
            </Box>

            <Paper variant="outlined" sx={{ p: 1.5 }}>
              <Stack spacing={1}>
                <Typography variant="subtitle2" sx={{ fontWeight: 900 }}>
                  Delen (cloud)
                </Typography>
                <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems="center">
                  <TextField
                    label="Email collega"
                    value={shareEmail}
                    onChange={(e) => setShareEmail(e.target.value)}
                    fullWidth
                  />
                  <TextField
                    select
                    label="Rechten"
                    value={sharePerm}
                    onChange={(e) => setSharePerm(e.target.value as 'read' | 'write')}
                    sx={{ minWidth: 140 }}
                  >
                    <MenuItem value="read">Read</MenuItem>
                    <MenuItem value="write">Write</MenuItem>
                  </TextField>
                </Stack>
                {shareStatus && (
                  <Alert severity={shareStatus === 'Gedeeld!' ? 'success' : 'info'}>{shareStatus}</Alert>
                )}
              </Stack>
            </Paper>

            <TextField
              select
              label="Link naar planning (optioneel)"
              value={
                noteLinks?.find((l) => l.toType === 'planning')?.toKey ?? ''
              }
              onChange={async (e) => {
                if (!draft.id) return
                const val = e.target.value as string
                // remove old planning links
                const existing = await db.links
                  .where('[ownerUserId+fromId]')
                  .equals([ownerUserId, draft.id] as [string, number])
                  .and((l) => l.fromType === 'note' && l.toType === 'planning')
                  .toArray()
                await db.links.bulkDelete(existing.map((x) => x.id!).filter(Boolean))
                if (val) {
                  await db.links.add({
                    ownerUserId,
                    fromType: 'note',
                    fromId: draft.id,
                    toType: 'planning',
                    toKey: val,
                    createdAt: Date.now(),
                  })
                }
              }}
            >
              <MenuItem value="">(geen)</MenuItem>
              {(planning ?? []).map((p) => (
                <MenuItem key={p.id} value={String(p.id)}>
                  {p.date} {p.start}-{p.end} • {p.title}
                </MenuItem>
              ))}
            </TextField>

            <Autocomplete
              multiple
              options={files ?? []}
              value={selectedFiles}
              isOptionEqualToValue={(o, v) => o.id === v.id}
              getOptionLabel={(o) => o.name}
              onChange={(_e, newValue) =>
                setDraft((d) => ({
                  ...d,
                  attachmentFileIds: newValue.map((f) => f.id!).filter(Boolean),
                }))
              }
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Bijlages (kies uit Bestanden)"
                  placeholder={files && files.length > 0 ? 'Selecteer...' : 'Geen bestanden geüpload'}
                />
              )}
            />

            {selectedFiles.length > 0 && (
              <Paper variant="outlined" sx={{ p: 1 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 800, mb: 1 }}>
                  Geselecteerde bijlages
                </Typography>
                <List dense disablePadding>
                  {selectedFiles.map((f) => (
                    <ListItemButton key={f.id} onClick={() => setPreview(f)}>
                      <ListItemText
                        primary={f.name}
                        secondary={`${formatBytes(f.size)} • ${f.type || 'onbekend'}`}
                      />
                      <ListItemSecondaryAction>
                        <IconButton aria-label="Preview" edge="end" onClick={() => setPreview(f)}>
                          <PreviewIcon />
                        </IconButton>
                        <IconButton
                          aria-label="Download"
                          edge="end"
                          onClick={() => downloadBlob(f.data, f.name)}
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
              >
                Verwijder
              </Button>
              <Button variant="contained" startIcon={<SaveIcon />} onClick={() => void save()}>
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
        files={selectedFiles}
        onClose={() => setNotePreviewOpen(false)}
      />
    </Box>
  )
}


