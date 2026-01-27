import LaunchIcon from '@mui/icons-material/Launch'
import { Alert, Box, Button, Chip, Divider, IconButton, MenuItem, Paper, Stack, TextField, Typography } from '@mui/material'
import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useSettings } from '../app/settings'
import { API_BASE, apiFetch, useApiToken } from '../api/client'
import { useWorkspace } from '../hooks/useWorkspace'
import { useWorkspaceEvents } from '../hooks/useWorkspaceEvents'
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
import { addDays, formatTimeRange, startOfWeekMonday, startOfWeekSunday, yyyyMmDdLocal } from '../utils/date'

const STAGE_WORK_TAG = 'stage:work'
const STAGE_HOME_TAG = 'stage:home'

function getStageType(rawTags: unknown) {
  try {
    let tags: string[] = []
    if (Array.isArray(rawTags)) {
      tags = rawTags.filter((t) => typeof t === 'string') as string[]
    } else if (typeof rawTags === 'string') {
      const trimmed = rawTags.trim()
      if (trimmed) {
        tags = JSON.parse(trimmed) as string[]
      }
    }
    if (tags.includes(STAGE_WORK_TAG)) return 'work'
    if (tags.includes(STAGE_HOME_TAG)) return 'home'
    return 'none'
  } catch {
    return 'none'
  }
}

function byDateTime(a: ServerPlanningItem, b: ServerPlanningItem) {
  return (a.date + a.start).localeCompare(b.date + b.start)
}

function Section({
  title,
  items,
  onOpenAll,
  onOpenItem,
  timeFormat,
}: {
  title: string
  items: ServerPlanningItem[]
  onOpenAll: () => void
  onOpenItem: (it: ServerPlanningItem) => void
  timeFormat?: '24h' | '12h'
}) {
  const top = items.slice(0, 8)
  return (
    <Paper variant="outlined" sx={{ p: { xs: 1.5, sm: 2 } }}>
      <Stack direction="column" spacing={{ xs: 1, sm: 1.5 }} sx={{ '@media (min-width:600px)': { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' } }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography sx={{ fontWeight: 900, fontSize: { xs: '0.875rem', sm: '1rem' } }}>{title}</Typography>
          <Chip size="small" label={items.length} sx={{ fontSize: { xs: '0.7rem', sm: '0.75rem' } }} />
        </Stack>
        <Button size="small" onClick={onOpenAll} sx={{ fontSize: { xs: '0.75rem', sm: '0.875rem' }, alignSelf: { xs: 'flex-start', sm: 'auto' } }}>
          Bekijk alles
        </Button>
      </Stack>
      <Divider sx={{ my: { xs: 1, sm: 1.5 } }} />
      {top.length === 0 ? (
        <Alert severity="info" sx={{ fontSize: { xs: '0.75rem', sm: '0.875rem' } }}>Geen items.</Alert>
      ) : (
        <Stack spacing={{ xs: 0.75, sm: 1 }}>
          {top.map((it) => (
            <Paper key={it.id} variant="outlined" sx={{ p: { xs: 1, sm: 1.25 } }}>
              <Stack direction="column" spacing={{ xs: 0.5, sm: 1 }} sx={{ '@media (min-width:600px)': { flexDirection: 'row', alignItems: 'center' } }}>
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Typography sx={{ fontWeight: 800, fontSize: { xs: '0.8125rem', sm: '0.875rem' } }} noWrap>
                    {it.date} {formatTimeRange(it.start, it.end, { format: timeFormat })} • {it.title}
                  </Typography>
                  {it.notes && (
                    <Typography variant="body2" color="text.secondary" noWrap sx={{ fontSize: { xs: '0.75rem', sm: '0.8125rem' } }}>
                      {it.notes}
                    </Typography>
                  )}
                </Box>
                <Stack direction="row" spacing={0.5} alignItems="center" sx={{ flexShrink: 0 }}>
                  <Chip
                    size="small"
                    label={it.priority === 'high' ? 'High' : it.priority === 'low' ? 'Low' : 'Medium'}
                    color={it.priority === 'high' ? 'error' : it.priority === 'low' ? 'default' : 'primary'}
                    variant={it.priority === 'low' ? 'outlined' : 'filled'}
                    sx={{ fontSize: { xs: '0.7rem', sm: '0.75rem' }, height: { xs: 20, sm: 24 } }}
                  />
                  <Chip
                    size="small"
                    label={it.status === 'done' ? 'Done' : it.status === 'in_progress' ? 'In progress' : 'Todo'}
                    color={it.status === 'done' ? 'success' : it.status === 'in_progress' ? 'warning' : 'default'}
                    variant="outlined"
                    sx={{ fontSize: { xs: '0.7rem', sm: '0.75rem' }, height: { xs: 20, sm: 24 }, display: { xs: 'none', sm: 'flex' } }}
                  />
                  <IconButton aria-label="Open" onClick={() => onOpenItem(it)} size="small" sx={{ padding: { xs: '4px', sm: '8px' } }}>
                    <LaunchIcon sx={{ fontSize: { xs: '1rem', sm: '1.25rem' } }} />
                  </IconButton>
                </Stack>
              </Stack>
            </Paper>
          ))}
        </Stack>
      )}
    </Paper>
  )
}

export function DashboardPage() {
  const nav = useNavigate()
  const { weekStart, timeFormat, stageStart, stageEnd } = useSettings()
  const token = useApiToken()
  const { currentWorkspace } = useWorkspace()
  const [items, setItems] = useState<ServerPlanningItem[]>([])
  const [refreshTick, setRefreshTick] = useState(0)
  const [exportFrom, setExportFrom] = useState(stageStart || '')
  const [exportTo, setExportTo] = useState(stageEnd || '')
  const [exportFormat, setExportFormat] = useState<'pdf' | 'csv'>('pdf')
  const [exportLoading, setExportLoading] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  useWorkspaceEvents((evt) => {
    if (evt.type === 'planning') setRefreshTick((v) => v + 1)
  })

  useEffect(() => {
    if (stageStart && !exportFrom) setExportFrom(stageStart)
  }, [stageStart, exportFrom])

  useEffect(() => {
    if (stageEnd && !exportTo) setExportTo(stageEnd)
  }, [stageEnd, exportTo])
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
      } catch {
        // ignore (offline etc)
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
  const itemsSorted = useMemo(() => {
    const list = items.slice()
    list.sort(byDateTime)
    return list
  }, [items])

  const now = new Date()
  const today = yyyyMmDdLocal(now)
  const nowMinutes = now.getHours() * 60 + now.getMinutes()
  const start = weekStart === 'sunday' ? startOfWeekSunday(now) : startOfWeekMonday(now)
  const weekStartYmd = yyyyMmDdLocal(start)
  const weekEnd = yyyyMmDdLocal(addDays(start, 6))

  const computed = useMemo(() => {
    const all = itemsSorted
    const notDone = all.filter((it) => it.status !== 'done')

    const todayItems = all.filter((it) => it.date === today).sort(byDateTime)
    const weekItems = all.filter((it) => it.date >= weekStartYmd && it.date <= weekEnd).sort(byDateTime)
    const highPriority = notDone.filter((it) => it.priority === 'high').sort(byDateTime)
    const overdue = notDone.filter((it) => it.date < today).sort(byDateTime)
    const inProgress = all.filter((it) => it.status === 'in_progress').sort(byDateTime)

    const stageWorkDates = new Set<string>()
    const stageWorkEndByDate = new Map<string, number>()
    for (const it of all) {
      const rawTags = (it as { tags?: unknown }).tags ?? it.tagsJson
      if (getStageType(rawTags) === 'work') {
        stageWorkDates.add(it.date)
        const endMatch = /^(\d{1,2}):(\d{2})$/.exec(it.end)
        if (endMatch) {
          const minutes = Number(endMatch[1]) * 60 + Number(endMatch[2])
          const prev = stageWorkEndByDate.get(it.date)
          stageWorkEndByDate.set(it.date, prev == null ? minutes : Math.max(prev, minutes))
        }
      }
    }
    const plannedStageDays = stageWorkDates.size
    const workedStageDays = Array.from(stageWorkDates).filter((d) => {
      if (d < today) return true
      if (d !== today) return false
      const endMinutes = stageWorkEndByDate.get(d)
      return endMinutes != null && endMinutes <= nowMinutes
    }).length

    const excludedStageDays = 0

    return {
      todayItems,
      weekItems,
      highPriority,
      overdue,
      inProgress,
      plannedStageDays,
      workedStageDays,
      excludedStageDays,
    }
  }, [itemsSorted, today, nowMinutes, weekStartYmd, weekEnd])

  async function downloadStageReport() {
    if (!token || !currentWorkspace?.id) return
    if (!exportFrom || !exportTo) {
      setExportError('Kies een geldige periode.')
      return
    }
    setExportLoading(true)
    setExportError(null)
    try {
      const url = `${API_BASE}/reports/stage?workspaceId=${encodeURIComponent(String(currentWorkspace.id))}&from=${encodeURIComponent(exportFrom)}&to=${encodeURIComponent(exportTo)}&format=${exportFormat}`
      const res = await fetch(url, {
        headers: { authorization: `Bearer ${token}` },
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        const code = data?.error || `http_${res.status}`
        if (code === 'range_too_large') {
          throw new Error('De gekozen periode is te groot (max 6 maanden).')
        }
        if (code === 'not_member') {
          throw new Error('Geen rechten voor deze workspace.')
        }
        throw new Error('Export mislukt. Controleer de parameters en probeer opnieuw.')
      }
      const blob = await res.blob()
      const filename = `stage-rapport-${exportFrom}-${exportTo}.${exportFormat}`
      const href = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = href
      link.download = filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(href)
    } catch (e) {
      setExportError(e instanceof Error ? e.message : 'Export mislukt.')
    } finally {
      setExportLoading(false)
    }
  }

  return (
    <Box sx={{ display: 'grid', gap: { xs: 1.5, sm: 2 } }}>
      <Stack direction="column" spacing={{ xs: 1.5, sm: 2 }} sx={{ '@media (min-width:900px)': { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' } }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800, fontSize: { xs: '1.125rem', sm: '1.25rem' } }}>
            Dashboard
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ fontSize: { xs: '0.75rem', sm: '0.875rem' } }}>
            Vandaag: <b>{today}</b> • Week: <b>{weekStartYmd}</b> – <b>{weekEnd}</b>
          </Typography>
        </Box>
        <Button variant="outlined" onClick={() => nav('/taken')} size="small" sx={{ alignSelf: { xs: 'stretch', md: 'flex-start' } }}>
          Naar taken-overzicht
        </Button>
      </Stack>

      {itemsSorted.length === 0 && <Alert severity="info">Geen items.</Alert>}

      <Paper variant="outlined" sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Stack direction="column" spacing={1}>
          <Typography sx={{ fontWeight: 900 }}>Stage voortgang</Typography>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }}>
            <Chip
              size="small"
              color="primary"
              label={`Ingepland: ${computed.plannedStageDays} / 60`}
            />
            <Chip
              size="small"
              color="success"
              label={`Gewerkt: ${computed.workedStageDays} / 60`}
            />
            <Chip
              size="small"
              label={`Nog te plannen: ${Math.max(0, 60 - computed.plannedStageDays)}`}
            />
          </Stack>
          <Typography variant="body2" color="text.secondary">
            Periode: {stageStart || 'onbekend'} – {stageEnd || 'onbekend'} •
            Gebruik planning met “Stage werkdag” om de 60 dagen bij te houden.
          </Typography>
          <Divider sx={{ my: 1 }} />
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }}>
            <TextField
              label="Van"
              type="date"
              value={exportFrom}
              onChange={(e) => setExportFrom(e.target.value)}
              InputLabelProps={{ shrink: true }}
              size="small"
            />
            <TextField
              label="Tot"
              type="date"
              value={exportTo}
              onChange={(e) => setExportTo(e.target.value)}
              InputLabelProps={{ shrink: true }}
              size="small"
            />
            <TextField
              label="Formaat"
              select
              value={exportFormat}
              onChange={(e) => setExportFormat(e.target.value as 'pdf' | 'csv')}
              size="small"
              sx={{ minWidth: 140 }}
            >
              <MenuItem value="pdf">PDF</MenuItem>
              <MenuItem value="csv">CSV</MenuItem>
            </TextField>
            <Button variant="contained" size="small" onClick={() => void downloadStageReport()} disabled={exportLoading}>
              {exportLoading ? 'Bezig...' : 'Exporteren'}
            </Button>
          </Stack>
          {exportError && (
            <Alert severity="error" sx={{ mt: 1 }}>
              {exportError}
            </Alert>
          )}
        </Stack>
      </Paper>

      <Box sx={{ display: 'grid', gridTemplateColumns: '1fr', gap: { xs: 1.5, sm: 2 }, '@media (min-width:1200px)': { gridTemplateColumns: '1fr 1fr' } }}>
        <Section
          title="Vandaag"
          items={computed.todayItems}
          timeFormat={timeFormat}
          onOpenAll={() => nav(`/planning?date=${encodeURIComponent(today)}`)}
          onOpenItem={(it) => nav(`/planning?date=${encodeURIComponent(it.date)}`)}
        />
        <Section
          title="Deze week"
          items={computed.weekItems}
          timeFormat={timeFormat}
          onOpenAll={() => nav('/week')}
          onOpenItem={(it) => nav(`/planning?date=${encodeURIComponent(it.date)}`)}
        />
        <Section
          title="High priority"
          items={computed.highPriority}
          timeFormat={timeFormat}
          onOpenAll={() => nav('/taken')}
          onOpenItem={(it) => nav(`/planning?date=${encodeURIComponent(it.date)}`)}
        />
        <Section
          title="Overdue"
          items={computed.overdue}
          timeFormat={timeFormat}
          onOpenAll={() => nav('/taken')}
          onOpenItem={(it) => nav(`/planning?date=${encodeURIComponent(it.date)}`)}
        />
        <Section
          title="In progress"
          items={computed.inProgress}
          timeFormat={timeFormat}
          onOpenAll={() => nav('/taken')}
          onOpenItem={(it) => nav(`/planning?date=${encodeURIComponent(it.date)}`)}
        />
      </Box>
    </Box>
  )
}


