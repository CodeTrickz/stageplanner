import LaunchIcon from '@mui/icons-material/Launch'
import { Alert, Box, Button, Chip, Divider, IconButton, Paper, Stack, Typography } from '@mui/material'
import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useSettings } from '../app/settings'
import { apiFetch, useApiToken } from '../api/client'
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
  const { weekStart, timeFormat, stageStart, stageEnd, stageHolidaysJson } = useSettings()
  const token = useApiToken()
  const { currentWorkspace } = useWorkspace()
  const [items, setItems] = useState<ServerPlanningItem[]>([])
  const [refreshTick, setRefreshTick] = useState(0)

  useWorkspaceEvents((evt) => {
    if (evt.type === 'planning') setRefreshTick((v) => v + 1)
  })
  const holidaySet = useMemo(() => {
    try {
      const arr = JSON.parse(stageHolidaysJson || '[]') as string[]
      return new Set((arr || []).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)))
    } catch {
      return new Set<string>()
    }
  }, [stageHolidaysJson])

  const isWithinStage = (d: string) => {
    if (!stageStart || !stageEnd) return true
    return d >= stageStart && d <= stageEnd
  }

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

  const today = yyyyMmDdLocal(new Date())
  const start = weekStart === 'sunday' ? startOfWeekSunday(new Date()) : startOfWeekMonday(new Date())
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
    for (const it of all) {
      const rawTags = (it as { tags?: unknown }).tags ?? it.tagsJson
      if (getStageType(rawTags) === 'work') {
        if (isWithinStage(it.date) && !holidaySet.has(it.date)) {
          stageWorkDates.add(it.date)
        }
      }
    }
    const plannedStageDays = stageWorkDates.size
    const workedStageDays = Array.from(stageWorkDates).filter((d) => d <= today).length

    const excludedStageDays = Array.from(holidaySet).filter((d) => isWithinStage(d)).length

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
  }, [itemsSorted, today, weekStartYmd, weekEnd, stageStart, stageEnd, holidaySet])

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
            {computed.excludedStageDays > 0 && (
              <Chip size="small" label={`Uitgesloten: ${computed.excludedStageDays}`} />
            )}
          </Stack>
          <Typography variant="body2" color="text.secondary">
            Periode: {stageStart || 'onbekend'} – {stageEnd || 'onbekend'} •
            Gebruik planning met “Stage werkdag” om de 60 dagen bij te houden.
          </Typography>
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


