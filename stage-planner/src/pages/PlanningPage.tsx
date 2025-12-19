import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline'
import EditOutlinedIcon from '@mui/icons-material/EditOutlined'
import {
  Alert,
  Autocomplete,
  Box,
  Button,
  Card,
  CardActions,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  MenuItem,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { useLiveQuery } from 'dexie-react-hooks'
import { useEffect, useMemo, useState } from 'react'

import { DayTimeline } from '../components/DayTimeline'
import { MonthCalendar } from '../components/MonthCalendar'
import { useSettings } from '../app/settings'
import { useAuth } from '../auth/auth'
import { db, type FileMeta, type PlanningItem } from '../db/db'
import { yyyyMmDdLocal } from '../utils/date'
import { apiFetch, useApiToken } from '../api/client'

type Draft = {
  id?: number
  date: string
  start: string
  end: string
  title: string
  notes: string
  priority: PlanningItem['priority']
  status: PlanningItem['status']
  tags: string
}

function toDraft(item: PlanningItem): Draft {
  return {
    id: item.id,
    date: item.date,
    start: item.start,
    end: item.end,
    title: item.title,
    notes: item.notes ?? '',
    priority: item.priority ?? 'medium',
    status: item.status ?? 'todo',
    tags: (() => {
      try {
        const arr = JSON.parse((item as any).tagsJson || '[]') as string[]
        return (arr || []).join(', ')
      } catch {
        return ''
      }
    })(),
  }
}

export function PlanningPage() {
  const { user } = useAuth()
  const token = useApiToken()
  const { defaultTaskMinutes, workdayStart, defaultPriority, defaultStatus, timeFormat } = useSettings()
  const userId = (user as any)?.id as string
  const ownerUserId = userId || '__local__'
  const [date, setDate] = useState(() => yyyyMmDdLocal(new Date()))
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState<Draft>(() => ({
    date: yyyyMmDdLocal(new Date()),
    start: '09:00',
    end: '10:00',
    title: '',
    notes: '',
    priority: defaultPriority ?? 'medium',
    status: defaultStatus ?? 'todo',
    tags: '',
  }))

  const items = useLiveQuery(
    async () => {
      const list = await db.planning.where('[ownerUserId+date]').equals([userId, date]).sortBy('start')
      return list
    },
    [userId, date],
    [],
  )

  const notes = useLiveQuery(async () => {
    const list = await db.notes.where('ownerUserId').equals(ownerUserId as any).toArray()
    list.sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0))
    return list
  }, [ownerUserId])

  const files = useLiveQuery(async () => {
    const list = await db.files.where('ownerUserId').equals(ownerUserId as any).toArray()
    list.sort((a, b) => (b.createdAt ?? 0) - (a.createdAt ?? 0))
    return list
  }, [ownerUserId])

  const metas = useLiveQuery(async () => {
    const list = await db.fileMeta.where('ownerUserId').equals(ownerUserId as any).toArray()
    return list
  }, [ownerUserId])

  const fileGroups = useMemo(() => {
    const map = new Map<string, { groupKey: string; name: string; type: string; latestCreatedAt: number }>()
    for (const f of files ?? []) {
      const cur = map.get(f.groupKey)
      if (!cur || (f.createdAt ?? 0) > cur.latestCreatedAt) {
        map.set(f.groupKey, { groupKey: f.groupKey, name: f.name, type: f.type, latestCreatedAt: f.createdAt })
      }
    }
    const metaByKey = new Map<string, FileMeta>()
    for (const m of metas ?? []) metaByKey.set(m.groupKey, m)
    return Array.from(map.values())
      .map((g) => ({ ...g, folder: metaByKey.get(g.groupKey)?.folder || '' }))
      .sort((a, b) => (b.latestCreatedAt ?? 0) - (a.latestCreatedAt ?? 0))
  }, [files, metas])

  const draftLinks = useLiveQuery(async () => {
    if (!draft.id) return { noteId: '', fileKeys: [] as string[] }
    const links = await db.links
      .where('[ownerUserId+fromId]')
      .equals([ownerUserId, draft.id] as any)
      .and((l) => l.fromType === 'planning')
      .toArray()
    const note = links.find((l) => l.toType === 'note')?.toKey ?? ''
    const fileKeys = links.filter((l) => l.toType === 'fileGroup').map((l) => l.toKey)
    return { noteId: note, fileKeys }
  }, [draft.id, ownerUserId])

  const [shareEmail, setShareEmail] = useState('')
  const [sharePerm, setSharePerm] = useState<'read' | 'write'>('read')
  const [shareStatus, setShareStatus] = useState<string | null>(null)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const qDate = params.get('date')
    if (qDate && /^\d{4}-\d{2}-\d{2}$/.test(qDate)) setDate(qDate)
  }, [])

  const validation = useMemo(() => {
    if (!draft.title.trim()) return 'Titel is verplicht.'
    if (!draft.start || !draft.end) return 'Start- en eindtijd zijn verplicht.'
    if (draft.start >= draft.end) return 'Eindtijd moet na starttijd liggen.'
    return null
  }, [draft])

  function startNew() {
    const [hh, mm] = (workdayStart || '09:00').split(':').map((x) => Number(x))
    const baseMins = (Number.isFinite(hh) ? hh : 9) * 60 + (Number.isFinite(mm) ? mm : 0)
    const endMins = baseMins + Math.min(8 * 60, Math.max(5, defaultTaskMinutes || 60))
    const startStr = `${String(Math.floor(baseMins / 60)).padStart(2, '0')}:${String(baseMins % 60).padStart(2, '0')}`
    const endStr = `${String(Math.floor(endMins / 60)).padStart(2, '0')}:${String(endMins % 60).padStart(2, '0')}`
    setDraft({
      date,
      start: startStr,
      end: endStr,
      title: '',
      notes: '',
      priority: defaultPriority ?? 'medium',
      status: defaultStatus ?? 'todo',
      tags: '',
    })
    setOpen(true)
  }

  async function save() {
    const err = validation
    if (err) return

    const now = Date.now()
    const tags = draft.tags
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 20)
    const basePayload = {
      date: draft.date,
      start: draft.start,
      end: draft.end,
      title: draft.title.trim(),
      notes: draft.notes.trim() ? draft.notes.trim() : undefined,
      priority: draft.priority,
      status: draft.status,
      tagsJson: JSON.stringify(tags),
      updatedAt: now,
    }

    if (draft.id) {
      await db.planning.update(draft.id, {
        ...basePayload,
      })
    } else {
      const payload: Omit<PlanningItem, 'id'> = {
        ownerUserId: userId,
        ...basePayload,
        createdAt: now,
      }
      const id = await db.planning.add(payload)
      setDraft((d) => ({ ...d, id }))
    }

    // Cloud sync (best effort)
    if (token) {
      const localId = draft.id ?? (await db.planning.where('updatedAt').equals(now).first())?.id
      if (localId) {
        const rec = await db.planning.get(localId)
        if (rec) {
          const remote = await apiFetch('/planning', {
            method: 'POST',
            token,
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              id: rec.remoteId,
              date: rec.date,
              start: rec.start,
              end: rec.end,
              title: rec.title,
              notes: rec.notes ?? null,
              priority: rec.priority,
              status: rec.status,
            }),
          })
          const remoteId = remote.item?.id as string | undefined
          if (remoteId && rec.remoteId !== remoteId) await db.planning.update(localId, { remoteId })
        }
      }
    }

    setOpen(false)
  }

  async function remove(id: number) {
    await db.planning.delete(id)
  }

  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      <Typography variant="h5" sx={{ fontWeight: 800 }}>
        Planning
      </Typography>

      <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems="stretch">
        <Box sx={{ width: { xs: '100%', md: 360 }, display: 'grid', gap: 2 }}>
          <MonthCalendar value={date} onChange={setDate} />
          <Paper variant="outlined" sx={{ p: 1.5 }}>
            <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between">
              <TextField
                label="Datum"
                type="date"
                value={date}
                onChange={(e) => setDate(e.target.value)}
                InputLabelProps={{ shrink: true }}
                sx={{ maxWidth: 200 }}
              />
              <Button variant="contained" onClick={startNew}>
                Nieuw item
              </Button>
            </Stack>
          </Paper>
        </Box>

        <Box sx={{ flex: 1, display: 'grid', gap: 2 }}>
          <DayTimeline
            items={(items ?? [])
              .filter((x) => typeof x.id === 'number')
              .map((it) => ({
                id: it.id as number,
                start: it.start,
                end: it.end,
                title: it.title,
                priority: it.priority ?? 'medium',
                status: it.status ?? 'todo',
              }))}
            onSelect={(t) => {
              const full = (items ?? []).find((x) => x.id === Number(t.id))
              if (!full) return
              setDraft(toDraft(full))
              setOpen(true)
            }}
            timeFormat={timeFormat}
          />
        </Box>
      </Stack>

      {items && items.length === 0 && (
        <Alert severity="info">
          Nog geen items voor <b>{date}</b>. Klik op <b>Nieuw item</b>.
        </Alert>
      )}

      <Box sx={{ display: 'grid', gap: 2 }}>
        {items?.map((it) => (
          <Card key={it.id} variant="outlined">
            <CardContent>
              <Stack
                direction={{ xs: 'column', sm: 'row' }}
                spacing={1}
                alignItems={{ xs: 'flex-start', sm: 'center' }}
                justifyContent="space-between"
              >
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    {it.start} – {it.end}
                  </Typography>
                  <Typography variant="h6" sx={{ fontWeight: 800 }}>
                    {it.title}
                  </Typography>
                  {it.notes && (
                    <Typography sx={{ mt: 0.5, whiteSpace: 'pre-wrap' }}>
                      {it.notes}
                    </Typography>
                  )}
                </Box>
                <Stack direction="row" spacing={1} sx={{ pt: { xs: 1, sm: 0 } }}>
                  <Chip
                    size="small"
                    label={it.priority === 'high' ? 'High' : it.priority === 'low' ? 'Low' : 'Medium'}
                    color={it.priority === 'high' ? 'error' : it.priority === 'low' ? 'default' : 'primary'}
                    variant={it.priority === 'low' ? 'outlined' : 'filled'}
                  />
                  <Chip
                    size="small"
                    label={
                      it.status === 'done'
                        ? 'Done'
                        : it.status === 'in_progress'
                          ? 'In progress'
                          : 'Todo'
                    }
                    color={it.status === 'done' ? 'success' : it.status === 'in_progress' ? 'warning' : 'default'}
                    variant="outlined"
                  />
                </Stack>
              </Stack>
              {(() => {
                try {
                  const tags = JSON.parse((it as any).tagsJson || '[]') as string[]
                  return tags?.length ? (
                    <Stack direction="row" spacing={1} sx={{ mt: 1 }} useFlexGap flexWrap="wrap">
                      {tags.slice(0, 6).map((t) => (
                        <Chip key={t} size="small" label={t} variant="outlined" />
                      ))}
                      {tags.length > 6 && <Chip size="small" label="…" variant="outlined" />}
                    </Stack>
                  ) : null
                } catch {
                  return null
                }
              })()}
            </CardContent>
            <CardActions sx={{ justifyContent: 'flex-end' }}>
              <IconButton
                aria-label="Bewerk"
                onClick={() => {
                  setDraft(toDraft(it))
                  setOpen(true)
                }}
              >
                <EditOutlinedIcon />
              </IconButton>
              <IconButton
                aria-label="Verwijder"
                onClick={() => it.id && remove(it.id)}
              >
                <DeleteOutlineIcon />
              </IconButton>
            </CardActions>
          </Card>
        ))}
      </Box>

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>{draft.id ? 'Planning item bewerken' : 'Nieuw planning item'}</DialogTitle>
        <DialogContent sx={{ display: 'grid', gap: 2, pt: 2 }}>
          <TextField
            label="Datum"
            type="date"
            value={draft.date}
            onChange={(e) => setDraft((d) => ({ ...d, date: e.target.value }))}
            InputLabelProps={{ shrink: true }}
          />
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              label="Start"
              type="time"
              value={draft.start}
              onChange={(e) => setDraft((d) => ({ ...d, start: e.target.value }))}
              InputLabelProps={{ shrink: true }}
              fullWidth
            />
            <TextField
              label="Einde"
              type="time"
              value={draft.end}
              onChange={(e) => setDraft((d) => ({ ...d, end: e.target.value }))}
              InputLabelProps={{ shrink: true }}
              fullWidth
            />
          </Stack>

          <TextField
            select
            label="Link notitie (optioneel)"
            value={draftLinks?.noteId ?? ''}
            onChange={async (e) => {
              if (!draft.id) return
              const val = e.target.value as string
              const existing = await db.links
                .where('[ownerUserId+fromId]')
                .equals([ownerUserId, draft.id] as any)
                .and((l) => l.fromType === 'planning' && l.toType === 'note')
                .toArray()
              await db.links.bulkDelete(existing.map((x) => x.id!).filter(Boolean))
              if (val) {
                await db.links.add({
                  ownerUserId,
                  fromType: 'planning',
                  fromId: draft.id,
                  toType: 'note',
                  toKey: val,
                  createdAt: Date.now(),
                })
              }
            }}
          >
            <MenuItem value="">(geen)</MenuItem>
            {(notes ?? []).map((n) => (
              <MenuItem key={n.id} value={String(n.id)}>
                {n.subject?.trim() ? n.subject : '(zonder onderwerp)'}
              </MenuItem>
            ))}
          </TextField>

          <Autocomplete
            multiple
            options={fileGroups}
            value={fileGroups.filter((g) => (draftLinks?.fileKeys ?? []).includes(g.groupKey))}
            isOptionEqualToValue={(o, v) => o.groupKey === v.groupKey}
            getOptionLabel={(o) => `${o.name}${o.folder ? ` • ${o.folder}` : ''}`}
            onChange={async (_e, newValue) => {
              if (!draft.id) return
              const existing = await db.links
                .where('[ownerUserId+fromId]')
                .equals([ownerUserId, draft.id] as any)
                .and((l) => l.fromType === 'planning' && l.toType === 'fileGroup')
                .toArray()
              await db.links.bulkDelete(existing.map((x) => x.id!).filter(Boolean))
              for (const g of newValue) {
                await db.links.add({
                  ownerUserId,
                  fromType: 'planning',
                  fromId: draft.id,
                  toType: 'fileGroup',
                  toKey: g.groupKey,
                  createdAt: Date.now(),
                })
              }
            }}
            renderInput={(params) => (
              <TextField {...params} label="Link bestanden (file groups)" placeholder="Selecteer..." />
            )}
          />
          <TextField
            label="Titel"
            value={draft.title}
            onChange={(e) => setDraft((d) => ({ ...d, title: e.target.value }))}
            autoFocus
          />
          <TextField
            label="Tags (comma separated)"
            value={draft.tags}
            onChange={(e) => setDraft((d) => ({ ...d, tags: e.target.value }))}
            helperText="Voorbeeld: School, Stage, Meeting"
          />
          <Paper variant="outlined" sx={{ p: 1.5 }}>
            <Stack spacing={1}>
              <Typography variant="subtitle2" sx={{ fontWeight: 900 }}>
                Delen (cloud)
              </Typography>
              {!token && (
                <Alert severity="info">Login vereist om te delen.</Alert>
              )}
              {token && (
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
                    onChange={(e) => setSharePerm(e.target.value as any)}
                    sx={{ minWidth: 140 }}
                  >
                    <MenuItem value="read">Read</MenuItem>
                    <MenuItem value="write">Write</MenuItem>
                  </TextField>
                  <Button
                    variant="contained"
                    disabled={!draft.id || !shareEmail}
                    onClick={async () => {
                      if (!draft.id) return
                      setShareStatus(null)
                      const rec = await db.planning.get(draft.id)
                      if (!rec?.remoteId) {
                        setShareStatus('Eerst opslaan (cloud sync) om te kunnen delen.')
                        return
                      }
                      try {
                        await apiFetch('/shares', {
                          method: 'POST',
                          token,
                          headers: { 'content-type': 'application/json' },
                          body: JSON.stringify({
                            resourceType: 'planning',
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
                </Stack>
              )}
              {shareStatus && <Alert severity={shareStatus === 'Gedeeld!' ? 'success' : 'warning'}>{shareStatus}</Alert>}
            </Stack>
          </Paper>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              select
              label="Prioriteit"
              value={draft.priority}
              onChange={(e) =>
                setDraft((d) => ({ ...d, priority: e.target.value as Draft['priority'] }))
              }
              fullWidth
            >
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
            </TextField>
            <TextField
              select
              label="Status"
              value={draft.status}
              onChange={(e) =>
                setDraft((d) => ({ ...d, status: e.target.value as Draft['status'] }))
              }
              fullWidth
            >
              <MenuItem value="todo">Todo</MenuItem>
              <MenuItem value="in_progress">In progress</MenuItem>
              <MenuItem value="done">Done</MenuItem>
            </TextField>
          </Stack>
          <TextField
            label="Notities (optioneel)"
            value={draft.notes}
            onChange={(e) => setDraft((d) => ({ ...d, notes: e.target.value }))}
            multiline
            minRows={4}
          />
          {validation && <Alert severity="warning">{validation}</Alert>}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Annuleer</Button>
          <Button variant="contained" onClick={save} disabled={!!validation}>
            Opslaan
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}


