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
import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { FilePreviewDialog } from '../components/FilePreviewDialog'
import type { StoredFile } from '../db/db'
import { apiFetch, useApiToken } from '../api/client'
import { categoryLabel, categoryOrder, fetchFileBlob, fileCategory, formatBytes, type FileCategory } from '../utils/files'
import { makeGroupKey } from '../utils/groupKey'
import { useWorkspace } from '../hooks/useWorkspace'
import { useWorkspaceEvents } from '../hooks/useWorkspaceEvents'

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

export function FilesPage() {
  const [params] = useSearchParams()
  const inputRef = useRef<HTMLInputElement | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [preview, setPreview] = useState<StoredFile | null>(null)
  const token = useApiToken()
  const { currentWorkspace } = useWorkspace()
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
  const [files, setFiles] = useState<ServerFile[]>([])
  const [metas, setMetas] = useState<ServerFileMeta[]>([])
  const [refreshTick, setRefreshTick] = useState(0)

  useWorkspaceEvents((evt) => {
    if (['files', 'file_meta'].includes(evt.type)) {
      setRefreshTick((v) => v + 1)
    }
  })

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
    const interval = setInterval(() => {
      if (!cancelled) void sync()
    }, 30000)
    return () => {
      cancelled = true
      clearInterval(interval)
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

  const metaByKey = useMemo(() => {
    const map = new Map<string, ServerFileMeta>()
    for (const m of metas ?? []) map.set(m.groupKey, m)
    return map
  }, [metas])

  const totalSize = useMemo(() => {
    if (!files) return 0
    return files.reduce((acc, f) => acc + (f.size ?? 0), 0)
  }, [files])

  async function auditFiles(
    action: 'upload' | 'download' | 'delete',
    list: Array<{ name: string; type?: string | null; size?: number | null; groupKey?: string | null; version?: number | null }>,
  ) {
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
            type: f.type ?? null,
            size: f.size ?? null,
            groupKey: f.groupKey ?? null,
            version: f.version ?? null,
          })),
        }),
      })
    } catch {
      // ignore (offline etc)
    }
  }

  async function downloadRemote(file: ServerFile) {
    if (!token) {
      setError('Bestand kan niet worden gedownload (geen server-id of login).')
      return
    }
    try {
      const blob = await fetchFileBlob(file.id, token)
      downloadBlob(blob, file.name)
      void auditFiles('download', [file])
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Download mislukt.')
    }
  }

  async function onPickFiles(fileList: FileList | null) {
    setError(null)
    if (!token) {
      setError('Login vereist om bestanden op de server te bewaren.')
      return
    }
    if (!currentWorkspace?.id) {
      setError('Selecteer een werkgroep om bestanden te uploaden.')
      return
    }
    if (!fileList || fileList.length === 0) return

    const workspaceId = String(currentWorkspace.id)
    const uploadItems: Array<{
      file: File
      name: string
      type: string
      size: number
      groupKey: string
      version: number
    }> = []

    for (const f of Array.from(fileList)) {
      const type = f.type || 'application/octet-stream'
      const groupKey = makeGroupKey(f.name, type, workspaceId)
      const versions = files.filter((x) => x.groupKey === groupKey)
      const lastVersion = versions.reduce((acc, cur) => Math.max(acc, cur.version ?? 0), 0)
      const version = lastVersion + 1
      uploadItems.push({ file: f, name: f.name, type, size: f.size, groupKey, version })
    }

    try {
      for (const item of uploadItems) {
        try {
          const arrayBuffer = await item.file.arrayBuffer()
          const base64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)))
          const remote = await apiFetch('/files', {
            method: 'POST',
            token: token || undefined,
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              name: item.name,
              type: item.type,
              size: item.size,
              groupKey: item.groupKey,
              version: item.version,
              workspaceId,
              data: base64,
            }),
          })
          const remoteFile = remote.file as ServerFile | undefined
          if (remoteFile) {
            setFiles((prev) => [remoteFile, ...prev])
          }
        } catch (e) {
          if (import.meta.env.DEV) {
            console.error('Failed to upload file to backend:', e)
          }
        }
      }
      void auditFiles('upload', uploadItems.map((i) => ({ name: i.name, type: i.type, size: i.size, groupKey: i.groupKey, version: i.version })))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Uploaden mislukt.')
    } finally {
      if (inputRef.current) inputRef.current.value = ''
    }
  }

  async function remove(id: string) {
    if (!token) return
    try {
      await apiFetch(`/files/${id}`, {
        method: 'DELETE',
        token: token || undefined,
      })
      const removed = files.find((f) => f.id === id)
      if (removed) void auditFiles('delete', [removed])
      setFiles((prev) => prev.filter((f) => f.id !== id))
    } catch (e) {
      if (import.meta.env.DEV) {
        console.error('Failed to delete file from backend:', e)
      }
    }
  }

  async function saveMeta(groupKey: string) {
    if (!token || !currentWorkspace?.id) return
    const labels = editLabels
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 20)
    try {
      const result = await apiFetch('/file-meta', {
        method: 'POST',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          workspaceId: String(currentWorkspace.id),
          groupKey,
          folder: editFolder.trim(),
          labelsJson: JSON.stringify(labels),
        }),
      })
      const item = result.item as ServerFileMeta | undefined
      if (item) {
        setMetas((prev) => {
          const idx = prev.findIndex((m) => m.groupKey === item.groupKey)
          if (idx >= 0) {
            const next = prev.slice()
            next[idx] = item
            return next
          }
          return [item, ...prev]
        })
      }
    } catch (e) {
      if (import.meta.env.DEV) {
        console.error('Failed to save file meta:', e)
      }
    }
    setEditing(null)
  }

  const folders = useMemo(() => {
    const set = new Set<string>()
    for (const m of metas ?? []) if (m.folder) set.add(m.folder)
    return Array.from(set).sort((a, b) => a.localeCompare(b))
  }, [metas])

  const groupedByCat = useMemo(() => {
    if (!files) return []
    const byGroup = new Map<string, ServerFile[]>()
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
      const cat = fileCategory(toStoredFile(g.latest))
      const arr = byCat.get(cat) ?? []
      arr.push(g)
      byCat.set(cat, arr)
    }
    return Array.from(byCat.entries())
      .sort((a, b) => categoryOrder(a[0]) - categoryOrder(b[0]))
      .map(([cat, list]) => ({ cat, list }))
  }, [files, q, folder, sort, metaByKey])

  return (
    <Box sx={{ display: 'grid', gap: { xs: 1.5, sm: 2 } }}>
      <Typography variant="h5" sx={{ fontWeight: 800, fontSize: { xs: '1.125rem', sm: '1.25rem' } }}>
        Bestanden
      </Typography>

      {!token && (
        <Alert severity="info">Login vereist om bestanden te laden en op te slaan voor de werkgroep.</Alert>
      )}

      <Paper sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Stack
          direction="column"
          spacing={{ xs: 1.5, sm: 2 }}
          sx={{ '@media (min-width:600px)': { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' } }}
        >
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
              Upload & download (server)
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Bestanden worden centraal opgeslagen. Totaal: <b>{formatBytes(totalSize)}</b>
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
              disabled={!token || !currentWorkspace?.id}
              onClick={() => inputRef.current?.click()}
            >
              Upload bestanden
            </Button>
          </Box>
        </Stack>
      </Paper>

      <Paper variant="outlined" sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Stack direction="column" spacing={{ xs: 1.5, sm: 2 }} sx={{ '@media (min-width:900px)': { flexDirection: 'row', alignItems: 'center' } }}>
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
            onChange={(e) => setSort(e.target.value as 'recent' | 'name')}
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
                    <IconButton aria-label="Preview" onClick={() => setPreview(toStoredFile(g.latest))}>
                      <PreviewIcon />
                    </IconButton>
                    <IconButton
                      aria-label="Download"
                      onClick={() => {
                        void downloadRemote(g.latest)
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
                        <IconButton aria-label="Preview" onClick={() => setPreview(toStoredFile(v))}>
                          <PreviewIcon />
                        </IconButton>
                        <IconButton
                          aria-label="Download"
                          onClick={() => {
                            void downloadRemote(v)
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


