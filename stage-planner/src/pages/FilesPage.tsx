import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline'
import DownloadIcon from '@mui/icons-material/Download'
import EditOutlinedIcon from '@mui/icons-material/EditOutlined'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import PreviewIcon from '@mui/icons-material/Preview'
import UploadFileIcon from '@mui/icons-material/UploadFile'
import {
  Alert,
  Box,
  Button,
  Chip,
  Collapse,
  Divider,
  IconButton,
  MenuItem,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { useLiveQuery } from 'dexie-react-hooks'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { FilePreviewDialog } from '../components/FilePreviewDialog'
import { db, type FileMeta, type StoredFile } from '../db/db'
import { apiFetch, useApiToken } from '../api/client'
import { categoryLabel, categoryOrder, fileCategory, formatBytes, type FileCategory } from '../utils/files'
import { makeGroupKey } from '../utils/groupKey'
import { useAuth } from '../auth/auth'

function downloadBlob(blob: Blob, filename: string) {
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
}

export function FilesPage() {
  const [params] = useSearchParams()
  const inputRef = useRef<HTMLInputElement | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [preview, setPreview] = useState<StoredFile | null>(null)
  const token = useApiToken()
  const { user } = useAuth()
  const ownerUserId = user?.id || null
  const [q, setQ] = useState('')
  const [folder, setFolder] = useState<string>('__all__')
  const [sort, setSort] = useState<'recent' | 'name'>('recent')
  // allow global search to prefill query (?q=)
  useEffect(() => {
    const qq = params.get('q')
    if (qq) setQ(qq)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [editing, setEditing] = useState<string | null>(null)
  const [editFolder, setEditFolder] = useState('')
  const [editLabels, setEditLabels] = useState('')

  const files = useLiveQuery(async () => {
    if (!ownerUserId) return []
    const list = await db.files.where('ownerUserId').equals(ownerUserId as any).toArray()
    const scoped = list.filter((f) => {
      const k = String((f as any).groupKey || '')
      // New format: u:<ownerUserId>::...
      if (k.startsWith('u:')) return k.startsWith(`u:${ownerUserId}::`)
      // Legacy keys: fall back to ownerUserId column only
      return true
    })
    scoped.sort((a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0))
    return scoped
  }, [ownerUserId])

  const metas = useLiveQuery(async () => {
    if (!ownerUserId) return []
    const list = await db.fileMeta.where('ownerUserId').equals(ownerUserId as any).toArray()
    return list
  }, [ownerUserId])

  const metaByKey = useMemo(() => {
    const map = new Map<string, FileMeta>()
    for (const m of metas ?? []) map.set(m.groupKey, m)
    return map
  }, [metas])

  const totalSize = useMemo(() => {
    if (!files) return 0
    return files.reduce((acc, f) => acc + (f.size ?? 0), 0)
  }, [files])

  async function auditFiles(action: 'upload' | 'download' | 'delete', list: Array<Partial<StoredFile> & { name: string }>) {
    if (!token) return
    try {
      await apiFetch('/audit/files', {
        method: 'POST',
        token,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          action,
          files: list.slice(0, 50).map((f) => ({
            name: f.name,
            type: (f as any).type ?? null,
            size: (f as any).size ?? null,
            groupKey: (f as any).groupKey ?? null,
            version: (f as any).version ?? null,
          })),
        }),
      })
    } catch {
      // ignore (offline etc)
    }
  }

  async function onPickFiles(fileList: FileList | null) {
    setError(null)
    if (!ownerUserId) {
      setError('Login vereist om bestanden te uploaden.')
      return
    }
    if (!fileList || fileList.length === 0) return

    const now = Date.now()
    const items: Omit<StoredFile, 'id'>[] = []
    const metaToUpsert: FileMeta[] = []

    for (const f of Array.from(fileList)) {
      const type = f.type || 'application/octet-stream'
      const groupKey = makeGroupKey(f.name, type, ownerUserId)
      const versions = await db.files.where('groupKey').equals(groupKey).sortBy('version')
      const last = versions.length ? versions[versions.length - 1] : undefined
      const version = (last?.version ?? 0) + 1

      items.push({
        ownerUserId,
        name: f.name,
        type,
        size: f.size,
        data: f,
        createdAt: now,
        groupKey,
        version,
      })

      if (!metaByKey.has(groupKey)) {
        metaToUpsert.push({
          groupKey,
          ownerUserId,
          folder: '',
          labelsJson: '[]',
          createdAt: now,
          updatedAt: now,
        })
      }
    }

    try {
      if (metaToUpsert.length) await db.fileMeta.bulkPut(metaToUpsert)
      await db.files.bulkAdd(items)
      void auditFiles('upload', items)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Uploaden mislukt.')
    } finally {
      if (inputRef.current) inputRef.current.value = ''
    }
  }

  async function remove(id: number) {
    const f = await db.files.get(id)
    await db.files.delete(id)
    if (f) void auditFiles('delete', [f])
  }

  async function saveMeta(groupKey: string) {
    if (!ownerUserId) return
    const now = Date.now()
    const labels = editLabels
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 20)
    const existing = metaByKey.get(groupKey)
    const meta: FileMeta = existing
      ? { ...existing, ownerUserId, folder: editFolder.trim(), labelsJson: JSON.stringify(labels), updatedAt: now }
      : { groupKey, ownerUserId, folder: editFolder.trim(), labelsJson: JSON.stringify(labels), createdAt: now, updatedAt: now }
    await db.fileMeta.put(meta)
    setEditing(null)
  }

  const folders = useMemo(() => {
    const set = new Set<string>()
    for (const m of metas ?? []) if (m.folder) set.add(m.folder)
    return Array.from(set).sort((a, b) => a.localeCompare(b))
  }, [metas])

  const groupedByCat = useMemo(() => {
    if (!files) return []
    const byGroup = new Map<string, StoredFile[]>()
    for (const f of files) {
      const arr = byGroup.get(f.groupKey) ?? []
      arr.push(f)
      byGroup.set(f.groupKey, arr)
    }

    const qq = q.trim().toLowerCase()
    const groups = Array.from(byGroup.entries()).map(([groupKey, versions]) => {
      versions.sort((a, b) => (b.version ?? 0) - (a.version ?? 0))
      const latest = versions[0]
      const meta = metaByKey.get(groupKey)
      const labels = meta ? (JSON.parse(meta.labelsJson || '[]') as string[]) : []
      return { groupKey, latest, versions, meta, labels }
    })

    const filtered = groups.filter((g) => {
      const metaFolder = g.meta?.folder || ''
      if (folder !== '__all__' && metaFolder !== folder) return false
      if (!qq) return true
      const hay = `${g.latest.name} ${g.latest.type} ${metaFolder} ${(g.labels || []).join(' ')}`.toLowerCase()
      return hay.includes(qq)
    })

    filtered.sort((a, b) => {
      if (sort === 'recent') return (b.latest.createdAt ?? 0) - (a.latest.createdAt ?? 0)
      return a.latest.name.localeCompare(b.latest.name)
    })

    // category grouping based on latest file type
    const byCat = new Map<FileCategory, typeof filtered>()
    for (const g of filtered) {
      const cat = fileCategory(g.latest)
      const arr = byCat.get(cat) ?? []
      arr.push(g)
      byCat.set(cat, arr)
    }
    return Array.from(byCat.entries())
      .sort((a, b) => categoryOrder(a[0]) - categoryOrder(b[0]))
      .map(([cat, list]) => ({ cat, list }))
  }, [files, q, folder, sort, metaByKey])

  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      <Typography variant="h5" sx={{ fontWeight: 800 }}>
        Bestanden
      </Typography>

      {!ownerUserId && (
        <Alert severity="info">
          Login vereist: bestanden zijn per gebruiker privé. De uploader ziet zijn bestanden; andere users (ook admin) niet.
        </Alert>
      )}

      <Paper sx={{ p: 2 }}>
        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          spacing={2}
          alignItems={{ xs: 'stretch', sm: 'center' }}
          justifyContent="space-between"
        >
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
              Upload & download (lokaal)
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Bestanden worden opgeslagen in je browser (IndexedDB). Totaal:{' '}
              <b>{formatBytes(totalSize)}</b>
            </Typography>
          </Box>

          <Box>
            <input
              ref={inputRef}
              hidden
              type="file"
              multiple
              onChange={(e) => void onPickFiles(e.target.files)}
            />
            <Button
              variant="contained"
              startIcon={<UploadFileIcon />}
              disabled={!ownerUserId}
              onClick={() => inputRef.current?.click()}
            >
              Upload bestanden
            </Button>
          </Box>
        </Stack>
      </Paper>

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems="center">
          <TextField
            label="Zoeken (naam/type/folder/labels)"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            fullWidth
          />
          <TextField
            select
            label="Folder"
            value={folder}
            onChange={(e) => setFolder(e.target.value)}
            sx={{ minWidth: 220 }}
          >
            <MenuItem value="__all__">Alle folders</MenuItem>
            <MenuItem value="">(geen folder)</MenuItem>
            {folders.map((f) => (
              <MenuItem key={f} value={f}>
                {f}
              </MenuItem>
            ))}
          </TextField>
          <TextField
            select
            label="Sorteren"
            value={sort}
            onChange={(e) => setSort(e.target.value as any)}
            sx={{ minWidth: 180 }}
          >
            <MenuItem value="recent">Recent</MenuItem>
            <MenuItem value="name">Naam</MenuItem>
          </TextField>
        </Stack>
      </Paper>

      {error && <Alert severity="error">{error}</Alert>}

      {files && files.length === 0 && (
        <Alert severity="info">Nog geen bestanden geüpload.</Alert>
      )}

      <Box sx={{ display: 'grid', gap: 1 }}>
        {groupedByCat.map(({ cat, list }) => (
          <Box key={cat} sx={{ display: 'grid', gap: 1 }}>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1 }}>
              <Typography sx={{ fontWeight: 900 }}>{categoryLabel(cat)}</Typography>
              <Chip size="small" label={list.length} />
            </Stack>
            <Divider />
            {list.map((g) => (
              <Paper
                key={g.groupKey}
                variant="outlined"
                sx={{ p: 1.5, display: 'grid', gap: 1 }}
              >
                <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ xs: 'stretch', sm: 'center' }}>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Typography sx={{ fontWeight: 800 }} noWrap>
                      {g.latest.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" noWrap>
                      v{g.latest.version} • {formatBytes(g.latest.size)} • {g.latest.type || 'onbekend'} •{' '}
                      {new Date(g.latest.createdAt).toLocaleString()}
                    </Typography>
                    <Stack direction="row" spacing={1} sx={{ mt: 0.75 }} useFlexGap flexWrap="wrap">
                      <Chip size="small" label={`versies: ${g.versions.length}`} />
                      <Chip size="small" label={`folder: ${g.meta?.folder || '(geen)'}`} variant="outlined" />
                      {(g.labels || []).slice(0, 4).map((l) => (
                        <Chip key={l} size="small" label={l} variant="outlined" />
                      ))}
                      {(g.labels || []).length > 4 && <Chip size="small" label="…" variant="outlined" />}
                    </Stack>
                  </Box>

                  <Stack
                    direction="row"
                    spacing={0.5}
                    alignItems="center"
                    justifyContent="flex-end"
                    sx={{ width: { xs: '100%', sm: 'auto' }, flexWrap: 'wrap' }}
                  >
                    <IconButton
                      aria-label="Meta bewerken"
                      onClick={() => {
                        setEditing(g.groupKey)
                        setEditFolder(g.meta?.folder || '')
                        setEditLabels((g.labels || []).join(', '))
                        setExpanded((e) => ({ ...e, [g.groupKey]: true }))
                      }}
                    >
                      <EditOutlinedIcon />
                    </IconButton>
                    <IconButton aria-label="Preview" onClick={() => setPreview(g.latest)}>
                      <PreviewIcon />
                    </IconButton>
                    <IconButton
                      aria-label="Download"
                      onClick={() => {
                        void auditFiles('download', [g.latest])
                        downloadBlob(g.latest.data, g.latest.name)
                      }}
                    >
                      <DownloadIcon />
                    </IconButton>
                    <IconButton aria-label="Verwijder" onClick={() => g.latest.id && remove(g.latest.id)}>
                      <DeleteOutlineIcon />
                    </IconButton>
                    <IconButton
                      aria-label="Versies tonen"
                      onClick={() => setExpanded((e) => ({ ...e, [g.groupKey]: !e[g.groupKey] }))}
                    >
                      <ExpandMoreIcon />
                    </IconButton>
                  </Stack>
                </Stack>

                <Collapse in={!!expanded[g.groupKey]} timeout="auto" unmountOnExit>
                  <Box sx={{ display: 'grid', gap: 1 }}>
                    {editing === g.groupKey && (
                      <Paper variant="outlined" sx={{ p: 1.5 }}>
                        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems="center">
                          <TextField
                            label="Folder"
                            value={editFolder}
                            onChange={(e) => setEditFolder(e.target.value)}
                            sx={{ minWidth: 220 }}
                          />
                          <TextField
                            label="Labels (comma separated)"
                            value={editLabels}
                            onChange={(e) => setEditLabels(e.target.value)}
                            fullWidth
                          />
                          <Stack direction="row" spacing={1} justifyContent="flex-end">
                            <Button onClick={() => setEditing(null)}>Annuleer</Button>
                            <Button variant="contained" onClick={() => void saveMeta(g.groupKey)}>
                              Opslaan
                            </Button>
                          </Stack>
                        </Stack>
                      </Paper>
                    )}

                    <Typography variant="subtitle2" sx={{ fontWeight: 900 }}>
                      Versies
                    </Typography>
                    {g.versions.map((v) => (
                      <Paper
                        key={v.id}
                        variant="outlined"
                        sx={{ p: 1.25, display: 'flex', gap: 2, alignItems: 'center' }}
                      >
                        <Box sx={{ flex: 1, minWidth: 0 }}>
                          <Typography sx={{ fontWeight: 700 }} noWrap>
                            v{v.version} • {formatBytes(v.size)} • {new Date(v.createdAt).toLocaleString()}
                          </Typography>
                        </Box>
                        <IconButton aria-label="Preview" onClick={() => setPreview(v)}>
                          <PreviewIcon />
                        </IconButton>
                        <IconButton
                          aria-label="Download"
                          onClick={() => {
                            void auditFiles('download', [v])
                            downloadBlob(v.data, v.name)
                          }}
                        >
                          <DownloadIcon />
                        </IconButton>
                        <IconButton aria-label="Verwijder" onClick={() => v.id && remove(v.id)}>
                          <DeleteOutlineIcon />
                        </IconButton>
                      </Paper>
                    ))}
                  </Box>
                </Collapse>
              </Paper>
            ))}
          </Box>
        ))}
      </Box>

      <FilePreviewDialog open={!!preview} file={preview} onClose={() => setPreview(null)} />
    </Box>
  )
}


