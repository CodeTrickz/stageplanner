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
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  MenuItem,
  Paper,
  Snackbar,
  Stack,
  TextField,
  Typography,
  useMediaQuery,
  useTheme,
} from '@mui/material'
import { useEffect, useMemo, useState } from 'react'

import { DayTimeline } from '../components/DayTimeline'
import { MonthCalendar } from '../components/MonthCalendar'
import { useSettings } from '../app/settings'
import { useWorkspace } from '../hooks/useWorkspace'
import { dateFromYmdLocal, startOfWeekMonday, yyyyMmDdLocal } from '../utils/date'
import { apiFetch, useApiToken } from '../api/client'
import { useWorkspaceEvents } from '../hooks/useWorkspaceEvents'
import { getWorkspacePermissions } from '../utils/permissions'

type ServerPlanningItem = {
  id: string
  userId?: string
  date: string
  start: string
  end: string
  title: string
  notes?: string | null
  priority: 'low' | 'medium' | 'high'
  status: 'todo' | 'in_progress' | 'done'
  tagsJson?: string
  createdAt?: number
  updatedAt?: number
}

type ServerNote = {
  id: string
  subject: string
  body: string
  createdAt: number
  updatedAt: number
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

type TaskTemplate = {
  id: string
  title: string
  description?: string | null
  durationMinutes: number
  tags: string[]
  priority?: ServerPlanningItem['priority']
  status?: ServerPlanningItem['status']
}

type TaskTemplateDraft = {
  id?: string
  title: string
  description: string
  durationMinutes: number
  tags: string
  priority: ServerPlanningItem['priority']
  status: ServerPlanningItem['status']
}

type Draft = {
  id?: string
  date: string
  start: string
  end: string
  title: string
  notes: string
  priority: ServerPlanningItem['priority']
  status: ServerPlanningItem['status']
  tags: string
  stageType: 'none' | 'work' | 'home'
}

const STAGE_WORK_TAG = 'stage:work'
const STAGE_HOME_TAG = 'stage:home'

function stageTypeFromTags(tags: string[]) {
  if (tags.includes(STAGE_WORK_TAG)) return 'work'
  if (tags.includes(STAGE_HOME_TAG)) return 'home'
  return 'none'
}

function stripStageTags(tags: string[]) {
  return tags.filter((t) => t !== STAGE_WORK_TAG && t !== STAGE_HOME_TAG)
}

function toDraft(item: ServerPlanningItem): Draft {
  let tags: string[] = []
  try {
    tags = JSON.parse(item.tagsJson || '[]') as string[]
  } catch {
    tags = []
  }
  const stageType = stageTypeFromTags(tags)
  const cleaned = stripStageTags(tags)
  return {
    id: item.id,
    date: item.date,
    start: item.start,
    end: item.end,
    title: item.title,
    notes: item.notes ?? '',
    priority: item.priority ?? 'medium',
    status: item.status ?? 'todo',
    tags: (cleaned || []).join(', '),
    stageType,
  }
}

export function PlanningPage() {
  const theme = useTheme()
  const fullScreenDialog = useMediaQuery(theme.breakpoints.down('sm'))
  const token = useApiToken()
  const { currentWorkspace } = useWorkspace()
  const {
    defaultTaskMinutes,
    workdayStart,
    defaultPriority,
    defaultStatus,
    timeFormat,
  } = useSettings()
  const permissions = getWorkspacePermissions(currentWorkspace?.role)
  const canEdit = permissions.canEdit
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
    stageType: 'none',
  }))
  const [items, setItems] = useState<ServerPlanningItem[]>([])
  const [notes, setNotes] = useState<ServerNote[]>([])
  const [files, setFiles] = useState<ServerFile[]>([])
  const [metas, setMetas] = useState<ServerFileMeta[]>([])
  const [draftLinks, setDraftLinks] = useState<{ noteId: string; fileKeys: string[] }>({ noteId: '', fileKeys: [] })
  const [refreshTick, setRefreshTick] = useState(0)
  const [templates, setTemplates] = useState<TaskTemplate[]>([])
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>('')
  const [templatesLoading, setTemplatesLoading] = useState(false)
  const [templatesError, setTemplatesError] = useState<string | null>(null)
  const [templateDraft, setTemplateDraft] = useState<TaskTemplateDraft>({
    title: '',
    description: '',
    durationMinutes: 60,
    tags: '',
    priority: 'medium',
    status: 'todo',
  })
  const [templateSaving, setTemplateSaving] = useState(false)
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [lastSelectedId, setLastSelectedId] = useState<string | null>(null)
  const [bulkStatus, setBulkStatus] = useState<ServerPlanningItem['status'] | ''>('')
  const [bulkPriority, setBulkPriority] = useState<ServerPlanningItem['priority'] | ''>('')
  const [bulkTags, setBulkTags] = useState<string[]>([])
  const [bulkTagsTouched, setBulkTagsTouched] = useState(false)
  const [bulkLoading, setBulkLoading] = useState(false)
  const [bulkToast, setBulkToast] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)

  useWorkspaceEvents((evt) => {
    if (['planning', 'notes', 'files', 'file_meta', 'links'].includes(evt.type)) {
      setRefreshTick((v) => v + 1)
    }
  })

  async function fetchTemplates() {
    if (!token || !currentWorkspace?.id) {
      setTemplates([])
      setSelectedTemplateId('')
      return
    }
    setTemplatesLoading(true)
    setTemplatesError(null)
    try {
      const result = await apiFetch(`/task-templates?workspaceId=${encodeURIComponent(currentWorkspace.id)}`, {
        token: token || undefined,
      })
      const list = (result.templates || []) as TaskTemplate[]
      setTemplates(list)
      if (selectedTemplateId && !list.find((t) => t.id === selectedTemplateId)) {
        setSelectedTemplateId('')
      }
    } catch (e) {
      setTemplatesError(e instanceof Error ? e.message : 'failed_to_load_templates')
    } finally {
      setTemplatesLoading(false)
    }
  }

  useEffect(() => {
    void fetchTemplates()
  }, [token, currentWorkspace?.id])

  // Load planning items for current workspace
  useEffect(() => {
    if (!token || !currentWorkspace?.id) return
    const workspaceId = String(currentWorkspace.id)
    const url = `/planning?workspaceId=${encodeURIComponent(workspaceId)}`
    let cancelled = false
    async function sync() {
      try {
        const result = await apiFetch(url, { token: token || undefined })
        if (cancelled) return
        const remoteItems = (result.items || []) as ServerPlanningItem[]
        setItems(remoteItems)
      } catch (e) {
        if (import.meta.env.DEV) {
          console.error('Failed to load planning items:', e)
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
    return () => {
      cancelled = true
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

  // Load links for current draft
  useEffect(() => {
    if (!token || !currentWorkspace?.id || !draft.id) {
      setDraftLinks({ noteId: '', fileKeys: [] })
      return
    }
    const workspaceId = String(currentWorkspace.id)
    const url = `/links?workspaceId=${encodeURIComponent(workspaceId)}&fromType=planning&fromId=${encodeURIComponent(draft.id)}`
    let cancelled = false
    async function sync() {
      try {
        const result = await apiFetch(url, { token: token || undefined })
        if (cancelled) return
        const items = (result.items || []) as Array<{ toType: 'fileGroup' | 'note' | 'planning'; toKey: string }>
        const noteId = items.find((l) => l.toType === 'note')?.toKey ?? ''
        const fileKeys = items.filter((l) => l.toType === 'fileGroup').map((l) => l.toKey)
        setDraftLinks({ noteId, fileKeys })
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
  }, [token, currentWorkspace?.id, draft.id, refreshTick])

  const itemsForDate = useMemo(() => {
    const list = items.filter((it) => it.date === date)
    list.sort((a, b) => (a.start + a.end).localeCompare(b.start + b.end))
    return list
  }, [items, date])

  const tagOptions = useMemo(() => {
    const set = new Set<string>()
    for (const it of items) {
      try {
        const tags = JSON.parse(it.tagsJson || '[]') as string[]
        for (const tag of tags) {
          if (typeof tag === 'string' && tag.trim()) set.add(tag)
        }
      } catch {
        // ignore invalid tag payloads
      }
    }
    return Array.from(set).sort((a, b) => a.localeCompare(b))
  }, [items])

  const fileGroups = useMemo(() => {
    const map = new Map<string, { groupKey: string; name: string; type: string; latestCreatedAt: number }>()
    for (const f of files ?? []) {
      const cur = map.get(f.groupKey)
      if (!cur || (f.createdAt ?? 0) > cur.latestCreatedAt) {
        map.set(f.groupKey, { groupKey: f.groupKey, name: f.name, type: f.type, latestCreatedAt: f.createdAt })
      }
    }
    const metaByKey = new Map<string, ServerFileMeta>()
    for (const m of metas ?? []) metaByKey.set(m.groupKey, m)
    return Array.from(map.values())
      .map((g) => ({ ...g, folder: metaByKey.get(g.groupKey)?.folder || '' }))
      .sort((a, b) => (b.latestCreatedAt ?? 0) - (a.latestCreatedAt ?? 0))
  }, [files, metas])

  useEffect(() => {
    setSelectedIds([])
    setLastSelectedId(null)
  }, [date])

  useEffect(() => {
    if (selectedIds.length === 0) return
    const visibleIds = new Set(itemsForDate.map((it) => it.id))
    const next = selectedIds.filter((id) => visibleIds.has(id))
    if (next.length !== selectedIds.length) setSelectedIds(next)
  }, [itemsForDate, selectedIds])


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
    if (!canEdit) return
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
      stageType: 'none',
    })
    setOpen(true)
  }

  async function saveLinks(next: { noteId: string; fileKeys: string[] }) {
    if (!canEdit) return
    if (!token || !currentWorkspace?.id || !draft.id) {
      setDraftLinks(next)
      return
    }
    const workspaceId = String(currentWorkspace.id)
    const links = [
      ...(next.noteId ? [{ toType: 'note' as const, toKey: next.noteId }] : []),
      ...next.fileKeys.map((k) => ({ toType: 'fileGroup' as const, toKey: k })),
    ]
    try {
      await apiFetch('/links', {
        method: 'POST',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          workspaceId,
          fromType: 'planning',
          fromId: draft.id,
          links,
        }),
      })
      setDraftLinks(next)
    } catch (e) {
      if (import.meta.env.DEV) {
        console.error('Failed to save links:', e)
      }
    }
  }

  async function save() {
    if (!canEdit) return
    const err = validation
    if (err) return
    if (!token || !currentWorkspace?.id) return

    const now = Date.now()
    const baseTags = draft.tags
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 20)
    const tags = stripStageTags(baseTags)
    if (draft.stageType === 'work') tags.unshift(STAGE_WORK_TAG)
    if (draft.stageType === 'home') tags.unshift(STAGE_HOME_TAG)
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

    try {
      const result = await apiFetch(`/planning?workspaceId=${encodeURIComponent(currentWorkspace.id)}`, {
        method: 'POST',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          id: draft.id,
          ...basePayload,
          notes: basePayload.notes ?? null,
          workspaceId: currentWorkspace.id,
        }),
      })
      const item = result.item as ServerPlanningItem
      setItems((prev) => {
        const idx = prev.findIndex((p) => p.id === item.id)
        if (idx >= 0) {
          const next = prev.slice()
          next[idx] = item
          return next
        }
        return [...prev, item]
      })
      setDraft((d) => ({ ...d, id: item.id }))
      setOpen(false)
    } catch (e) {
      if (import.meta.env.DEV) {
        console.error('Failed to save planning item:', e)
      }
    }
  }

  async function remove(id: string) {
    if (!canEdit) return
    if (!token) return
    try {
      await apiFetch(`/planning/${id}`, {
        method: 'DELETE',
        token: token || undefined,
      })
      setItems((prev) => prev.filter((p) => p.id !== id))
    } catch (e) {
      if (import.meta.env.DEV) {
        console.error('Failed to delete planning item:', e)
      }
    }
  }

  function toggleSelection(id: string, checked: boolean, shiftKey: boolean) {
    const orderedIds = itemsForDate.map((it) => it.id)
    const next = new Set(selectedIds)
    if (shiftKey && lastSelectedId) {
      const start = orderedIds.indexOf(lastSelectedId)
      const end = orderedIds.indexOf(id)
      if (start >= 0 && end >= 0) {
        const [from, to] = start < end ? [start, end] : [end, start]
        for (const itemId of orderedIds.slice(from, to + 1)) {
          if (checked) next.add(itemId)
          else next.delete(itemId)
        }
      } else if (checked) {
        next.add(id)
      } else {
        next.delete(id)
      }
    } else if (checked) {
      next.add(id)
    } else {
      next.delete(id)
    }
    setSelectedIds(Array.from(next))
    setLastSelectedId(id)
  }

  async function applyBulkUpdate() {
    if (!canEdit) return
    if (!token || !currentWorkspace?.id) return
    const updates: { status?: ServerPlanningItem['status']; priority?: ServerPlanningItem['priority']; tags?: string[] } = {}
    if (bulkStatus) updates.status = bulkStatus
    if (bulkPriority) updates.priority = bulkPriority
    if (bulkTagsTouched) {
      updates.tags = bulkTags.map((t) => t.trim()).filter(Boolean).slice(0, 50)
    }

    if (Object.keys(updates).length === 0) {
      setBulkToast({ message: 'Kies minstens één veld om aan te passen.', severity: 'error' })
      return
    }
    if (selectedIds.length > 10) {
      const ok = window.confirm(`Je staat op het punt ${selectedIds.length} items bij te werken. Doorgaan?`)
      if (!ok) return
    }

    setBulkLoading(true)
    try {
      const result = await apiFetch('/planning/bulk', {
        method: 'PATCH',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          workspaceId: currentWorkspace.id,
          itemIds: selectedIds,
          updates,
        }),
      })
      const updatedCount = Number(result.updatedCount || 0)
      setItems((prev) =>
        prev.map((it) => {
          if (!selectedIds.includes(it.id)) return it
          return {
            ...it,
            status: updates.status ?? it.status,
            priority: updates.priority ?? it.priority,
            tagsJson: updates.tags ? JSON.stringify(updates.tags) : it.tagsJson,
            updatedAt: Date.now(),
          }
        }),
      )
      setSelectedIds([])
      setLastSelectedId(null)
      setBulkStatus('')
      setBulkPriority('')
      setBulkTags([])
      setBulkTagsTouched(false)
      setRefreshTick((v) => v + 1)
      setBulkToast({ message: `${updatedCount || selectedIds.length} items bijgewerkt.`, severity: 'success' })
    } catch (e) {
      setBulkToast({ message: 'Bulk update mislukt. Probeer opnieuw.', severity: 'error' })
      if (import.meta.env.DEV) {
        console.error('Failed to bulk update planning items:', e)
      }
    } finally {
      setBulkLoading(false)
    }
  }

  async function applyTemplateToWeek() {
    if (!canEdit) return
    if (!token || !currentWorkspace?.id || !selectedTemplateId) return
    const weekStart = yyyyMmDdLocal(startOfWeekMonday(dateFromYmdLocal(date)))
    try {
      const result = await apiFetch(`/task-templates/${selectedTemplateId}/apply`, {
        method: 'POST',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          workspaceId: currentWorkspace.id,
          weekStart,
        }),
      })
      setBulkToast({
        message: `Template toegepast (${result.createdCount ?? 0} items).`,
        severity: 'success',
      })
      setRefreshTick((v) => v + 1)
    } catch (e) {
      setBulkToast({
        message: e instanceof Error ? e.message : 'Template toepassen mislukt.',
        severity: 'error',
      })
    }
  }

  function resetTemplateDraft() {
    setTemplateDraft({ title: '', description: '', durationMinutes: 60, tags: '', priority: 'medium', status: 'todo' })
  }

  function startEditTemplate(template: TaskTemplate) {
    setTemplateDraft({
      id: template.id,
      title: template.title,
      description: template.description ?? '',
      durationMinutes: template.durationMinutes,
      tags: template.tags.join(', '),
      priority: template.priority ?? 'medium',
      status: template.status ?? 'todo',
    })
  }

  async function saveTemplate() {
    if (!canEdit) return
    if (!token || !currentWorkspace?.id) return
    if (!templateDraft.title.trim()) {
      setBulkToast({ message: 'Template titel is verplicht.', severity: 'error' })
      return
    }
    setTemplateSaving(true)
    try {
      const payload = {
        workspaceId: currentWorkspace.id,
        title: templateDraft.title.trim(),
        description: templateDraft.description.trim() || null,
        durationMinutes: Math.max(5, Math.min(600, Math.round(templateDraft.durationMinutes))),
        priority: templateDraft.priority,
        status: templateDraft.status,
        tags: templateDraft.tags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean)
          .slice(0, 50),
      }
      if (templateDraft.id) {
        await apiFetch(`/task-templates/${templateDraft.id}`, {
          method: 'PATCH',
          token: token || undefined,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            title: payload.title,
            description: payload.description,
            durationMinutes: payload.durationMinutes,
            priority: payload.priority,
            status: payload.status,
            tags: payload.tags,
          }),
        })
      } else {
        await apiFetch('/task-templates', {
          method: 'POST',
          token: token || undefined,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
        })
      }
      await fetchTemplates()
      resetTemplateDraft()
      setBulkToast({ message: 'Template opgeslagen.', severity: 'success' })
    } catch (e) {
      setBulkToast({
        message: e instanceof Error ? e.message : 'Template opslaan mislukt.',
        severity: 'error',
      })
    } finally {
      setTemplateSaving(false)
    }
  }

  async function deleteTemplate(templateId: string) {
    if (!canEdit) return
    if (!token) return
    const ok = window.confirm('Template verwijderen?')
    if (!ok) return
    try {
      await apiFetch(`/task-templates/${templateId}`, {
        method: 'DELETE',
        token: token || undefined,
      })
      if (selectedTemplateId === templateId) setSelectedTemplateId('')
      if (templateDraft.id === templateId) resetTemplateDraft()
      await fetchTemplates()
      setBulkToast({ message: 'Template verwijderd.', severity: 'success' })
    } catch (e) {
      setBulkToast({
        message: e instanceof Error ? e.message : 'Template verwijderen mislukt.',
        severity: 'error',
      })
    }
  }

  return (
    <Box sx={{ display: 'grid', gap: { xs: 1.5, sm: 2 } }}>
      <Typography variant="h5" sx={{ fontWeight: 800, fontSize: { xs: '1.125rem', sm: '1.25rem' } }}>
        Planning
      </Typography>

      <Stack direction="column" spacing={{ xs: 1.5, sm: 2 }} sx={{ '@media (min-width:900px)': { flexDirection: 'row', alignItems: 'stretch' } }}>
        <Box sx={{ width: '100%', display: 'grid', gap: { xs: 1.5, sm: 2 }, '@media (min-width:900px)': { width: 360 } }}>
          <MonthCalendar value={date} onChange={setDate} />
          <Paper variant="outlined" sx={{ p: { xs: 1, sm: 1.5 } }}>
            <Stack direction="column" spacing={{ xs: 1, sm: 1.5 }} sx={{ '@media (min-width:600px)': { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' } }}>
              <TextField
                label="Datum"
                type="date"
                value={date}
                onChange={(e) => setDate(e.target.value)}
                InputLabelProps={{ shrink: true }}
                size="small"
                sx={{ width: { xs: '100%', sm: 'auto' }, maxWidth: { xs: '100%', sm: 200 } }}
              />
              <Button
                variant="contained"
                onClick={startNew}
                size="small"
                disabled={!canEdit}
                sx={{ alignSelf: { xs: 'stretch', sm: 'auto' } }}
              >
                Nieuw item
              </Button>
            </Stack>
          </Paper>
          <Paper variant="outlined" sx={{ p: { xs: 1, sm: 1.5 } }}>
            <Stack direction="column" spacing={1}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                Templates
              </Typography>
              <TextField
                select
                label="Template"
                size="small"
                value={selectedTemplateId}
                onChange={(e) => setSelectedTemplateId(e.target.value)}
                disabled={templatesLoading || templates.length === 0}
              >
                <MenuItem value="">(selecteer)</MenuItem>
                {templates.map((t) => (
                  <MenuItem key={t.id} value={t.id}>
                    {t.title}
                  </MenuItem>
                ))}
              </TextField>
              {templatesError && <Alert severity="error">{templatesError}</Alert>}
              {selectedTemplateId && (
                <Typography variant="caption" color="text.secondary">
                  {templates.find((t) => t.id === selectedTemplateId)?.durationMinutes ?? 0} min • week van{' '}
                  {yyyyMmDdLocal(startOfWeekMonday(dateFromYmdLocal(date)))}
                </Typography>
              )}
              <Button
                variant="outlined"
                size="small"
                onClick={applyTemplateToWeek}
                disabled={!canEdit || !selectedTemplateId}
              >
                Toepassen op week
              </Button>
              {canEdit && (
                <Stack spacing={1} sx={{ pt: 0.5 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                    Template beheren
                  </Typography>
                  <TextField
                    label="Titel"
                    size="small"
                    value={templateDraft.title}
                    onChange={(e) => setTemplateDraft((d) => ({ ...d, title: e.target.value }))}
                    disabled={templateSaving}
                  />
                  <TextField
                    label="Beschrijving"
                    size="small"
                    value={templateDraft.description}
                    onChange={(e) => setTemplateDraft((d) => ({ ...d, description: e.target.value }))}
                    disabled={templateSaving}
                  />
                  <TextField
                    label="Duur (min)"
                    type="number"
                    size="small"
                    value={templateDraft.durationMinutes}
                    onChange={(e) => setTemplateDraft((d) => ({ ...d, durationMinutes: Number(e.target.value) }))}
                    inputProps={{ min: 5, max: 600 }}
                    disabled={templateSaving}
                  />
                  <TextField
                    select
                    label="Prioriteit"
                    size="small"
                    value={templateDraft.priority}
                    onChange={(e) =>
                      setTemplateDraft((d) => ({ ...d, priority: e.target.value as ServerPlanningItem['priority'] }))
                    }
                    disabled={templateSaving}
                  >
                    <MenuItem value="low">Low</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                  </TextField>
                  <TextField
                    select
                    label="Status"
                    size="small"
                    value={templateDraft.status}
                    onChange={(e) =>
                      setTemplateDraft((d) => ({ ...d, status: e.target.value as ServerPlanningItem['status'] }))
                    }
                    disabled={templateSaving}
                  >
                    <MenuItem value="todo">Todo</MenuItem>
                    <MenuItem value="in_progress">In progress</MenuItem>
                    <MenuItem value="done">Done</MenuItem>
                  </TextField>
                  <TextField
                    label="Tags (comma-separated)"
                    size="small"
                    value={templateDraft.tags}
                    onChange={(e) => setTemplateDraft((d) => ({ ...d, tags: e.target.value }))}
                    disabled={templateSaving}
                  />
                  <Stack direction="row" spacing={1}>
                    <Button variant="contained" size="small" onClick={saveTemplate} disabled={templateSaving}>
                      {templateDraft.id ? 'Bijwerken' : 'Aanmaken'}
                    </Button>
                    <Button variant="text" size="small" onClick={resetTemplateDraft} disabled={templateSaving}>
                      Wissen
                    </Button>
                  </Stack>
                </Stack>
              )}
              {templates.length > 0 && (
                <Stack spacing={0.5} sx={{ pt: 0.5 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                    Bestaande templates
                  </Typography>
                  {templates.map((t) => (
                    <Stack key={t.id} direction="row" spacing={1} alignItems="center" justifyContent="space-between">
                      <Typography variant="body2" noWrap sx={{ flex: 1 }}>
                        {t.title}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {t.durationMinutes} min • {t.priority ?? 'medium'} • {t.status ?? 'todo'}
                      </Typography>
                      {canEdit && (
                        <Stack direction="row" spacing={0.5}>
                          <Button size="small" onClick={() => startEditTemplate(t)}>
                            Bewerken
                          </Button>
                          <Button size="small" color="error" onClick={() => void deleteTemplate(t.id)}>
                            Verwijder
                          </Button>
                        </Stack>
                      )}
                    </Stack>
                  ))}
                </Stack>
              )}
            </Stack>
          </Paper>
        </Box>

        <Box sx={{ flex: 1, display: 'grid', gap: 2 }}>
          <DayTimeline
            items={itemsForDate.map((it) => ({
              id: it.id,
              start: it.start,
              end: it.end,
              title: it.title,
              priority: it.priority ?? 'medium',
              status: it.status ?? 'todo',
            }))}
            onSelect={(t) => {
            if (!canEdit) return
              const full = itemsForDate.find((x) => x.id === String(t.id))
              if (!full) return
              setDraft(toDraft(full))
              setOpen(true)
            }}
            timeFormat={timeFormat}
          />
        </Box>
      </Stack>

      {itemsForDate.length === 0 && (
        <Alert severity="info">
          Nog geen items voor <b>{date}</b>. Klik op <b>Nieuw item</b>.
        </Alert>
      )}

      {selectedIds.length > 0 && (
        <Paper variant="outlined" sx={{ p: 1.5 }}>
          <Stack
            direction={{ xs: 'column', sm: 'row' }}
            spacing={1.5}
            alignItems={{ xs: 'stretch', sm: 'center' }}
            useFlexGap
            flexWrap="wrap"
          >
            <Typography sx={{ fontWeight: 700 }}>{selectedIds.length} geselecteerd</Typography>
            <TextField
              label="Status"
              select
              size="small"
              value={bulkStatus}
              onChange={(e) => setBulkStatus(e.target.value as ServerPlanningItem['status'] | '')}
              sx={{ minWidth: 160 }}
              disabled={bulkLoading || !canEdit}
            >
              <MenuItem value="">Ongewijzigd</MenuItem>
              <MenuItem value="todo">Todo</MenuItem>
              <MenuItem value="in_progress">In progress</MenuItem>
              <MenuItem value="done">Done</MenuItem>
            </TextField>
            <TextField
              label="Prioriteit"
              select
              size="small"
              value={bulkPriority}
              onChange={(e) => setBulkPriority(e.target.value as ServerPlanningItem['priority'] | '')}
              sx={{ minWidth: 160 }}
              disabled={bulkLoading || !canEdit}
            >
              <MenuItem value="">Ongewijzigd</MenuItem>
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
            </TextField>
            <Autocomplete
              multiple
              freeSolo
              options={tagOptions}
              size="small"
              value={bulkTags}
              onChange={(_e, value) => {
                setBulkTags(value)
                setBulkTagsTouched(true)
              }}
              renderInput={(params) => <TextField {...params} label="Tags" placeholder="Tag toevoegen" />}
              sx={{ minWidth: 220, flex: 1 }}
              disabled={bulkLoading || !canEdit}
            />
            <Button
              variant="outlined"
              size="small"
              onClick={() => {
                setBulkTags([])
                setBulkTagsTouched(true)
              }}
              disabled={bulkLoading || !canEdit}
            >
              Tags wissen
            </Button>
            <Button variant="contained" size="small" onClick={applyBulkUpdate} disabled={bulkLoading || !canEdit}>
              {bulkLoading ? 'Bezig...' : 'Toepassen'}
            </Button>
            <Button
              variant="text"
              size="small"
              onClick={() => {
                setSelectedIds([])
                setLastSelectedId(null)
              }}
              disabled={bulkLoading || !canEdit}
            >
              Selectie wissen
            </Button>
          </Stack>
        </Paper>
      )}

      <Box sx={{ display: 'grid', gap: 2 }}>
        {itemsForDate.map((it) => (
          <Card key={it.id} variant="outlined">
            <CardContent>
              <Stack
                direction={{ xs: 'column', sm: 'row' }}
                spacing={1}
                alignItems={{ xs: 'flex-start', sm: 'center' }}
                justifyContent="space-between"
              >
                <Stack direction="row" spacing={1} alignItems="flex-start">
                  <Checkbox
                    size="small"
                    checked={selectedIds.includes(it.id)}
                    onChange={(e) => {
                      const native = e.nativeEvent as MouseEvent
                      toggleSelection(it.id, e.target.checked, !!native.shiftKey)
                    }}
                    inputProps={{ 'aria-label': 'Selecteer item' }}
                    disabled={!canEdit}
                  />
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
                </Stack>
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
                  const tags = JSON.parse(it.tagsJson || '[]') as string[]
                  const stageType = stageTypeFromTags(tags)
                  const visibleTags = stripStageTags(tags).filter((t) => {
                    const normalized = t.trim().toLowerCase()
                    return normalized !== 'niet-werkdag' && normalized !== 'non-workday'
                  })
                  return stageType !== 'none' || visibleTags.length ? (
                    <Stack direction="row" spacing={1} sx={{ mt: 1 }} useFlexGap flexWrap="wrap">
                      {stageType !== 'none' && (
                        <Chip
                          size="small"
                          label={stageType === 'work' ? 'Stage werkdag' : 'Thuis project'}
                          color={stageType === 'work' ? 'primary' : 'default'}
                          variant="outlined"
                        />
                      )}
                      {visibleTags.slice(0, 6).map((t) => (
                        <Chip key={t} size="small" label={t} variant="outlined" />
                      ))}
                      {visibleTags.length > 6 && <Chip size="small" label="…" variant="outlined" />}
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
                disabled={!canEdit}
              >
                <EditOutlinedIcon />
              </IconButton>
              <IconButton
                aria-label="Verwijder"
                onClick={() => it.id && remove(it.id)}
                disabled={!canEdit}
              >
                <DeleteOutlineIcon />
              </IconButton>
            </CardActions>
          </Card>
        ))}
      </Box>

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm" fullScreen={fullScreenDialog}>
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
              const val = e.target.value as string
              await saveLinks({ noteId: val, fileKeys: draftLinks.fileKeys })
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
              await saveLinks({ noteId: draftLinks.noteId, fileKeys: newValue.map((g) => g.groupKey) })
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
          <TextField
            select
            label="Stage dagtype"
            value={draft.stageType}
            onChange={(e) => setDraft((d) => ({ ...d, stageType: e.target.value as Draft['stageType'] }))}
            helperText="Werkdag telt mee voor de 60 dagen. Thuis project telt niet mee."
          >
            <MenuItem value="none">(geen)</MenuItem>
            <MenuItem value="work">Stage werkdag</MenuItem>
            <MenuItem value="home">Thuis project (geen werkdag)</MenuItem>
          </TextField>
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

      <Snackbar
        open={!!bulkToast}
        autoHideDuration={4000}
        onClose={() => setBulkToast(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert onClose={() => setBulkToast(null)} severity={bulkToast?.severity || 'success'} sx={{ width: '100%' }}>
          {bulkToast?.message}
        </Alert>
      </Snackbar>
    </Box>
  )
}


