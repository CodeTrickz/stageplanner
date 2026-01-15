import LaunchIcon from '@mui/icons-material/Launch'
import { Alert, Box, Button, Chip, Divider, IconButton, Paper, Stack, Typography } from '@mui/material'
import { useLiveQuery } from 'dexie-react-hooks'
import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useSettings } from '../app/settings'
import { useAuth } from '../auth/auth'
import { useWorkspace } from '../hooks/useWorkspace'
import { db, type PlanningItem } from '../db/db'
import { addDays, formatTimeRange, startOfWeekMonday, startOfWeekSunday, yyyyMmDdLocal } from '../utils/date'

const STAGE_WORK_TAG = 'stage:work'
const STAGE_HOME_TAG = 'stage:home'

function getStageType(tagsJson: string | undefined) {
  try {
    const tags = JSON.parse(tagsJson || '[]') as string[]
    if (tags.includes(STAGE_WORK_TAG)) return 'work'
    if (tags.includes(STAGE_HOME_TAG)) return 'home'
    return 'none'
  } catch {
    return 'none'
  }
}

function byDateTime(a: PlanningItem, b: PlanningItem) {
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
  items: PlanningItem[]
  onOpenAll: () => void
  onOpenItem: (it: PlanningItem) => void
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
  const { user } = useAuth()
  const { currentWorkspace } = useWorkspace()
  const userId = user?.id
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
  const items = useLiveQuery(async () => {
    if (!userId) return []
    // Filter by workspace if available, otherwise fallback to ownerUserId
    if (currentWorkspace?.id) {
      const list = await db.planning.where('workspaceId').equals(currentWorkspace.id).toArray()
      return list.sort(byDateTime)
    }
    // Fallback to ownerUserId for backward compatibility
    const list = await db.planning.where('ownerUserId').equals(userId).toArray()
    return list.sort(byDateTime)
  }, [userId, currentWorkspace?.id])

  const today = yyyyMmDdLocal(new Date())
  const start = weekStart === 'sunday' ? startOfWeekSunday(new Date()) : startOfWeekMonday(new Date())
  const weekStartYmd = yyyyMmDdLocal(start)
  const weekEnd = yyyyMmDdLocal(addDays(start, 6))

  const computed = useMemo(() => {
    const all = items ?? []
    const notDone = all.filter((it) => it.status !== 'done')

    const todayItems = all.filter((it) => it.date === today).sort(byDateTime)
    const weekItems = all.filter((it) => it.date >= weekStartYmd && it.date <= weekEnd).sort(byDateTime)
    const highPriority = notDone.filter((it) => it.priority === 'high').sort(byDateTime)
    const overdue = notDone.filter((it) => it.date < today).sort(byDateTime)
    const inProgress = all.filter((it) => it.status === 'in_progress').sort(byDateTime)

    const stageWorkDates = new Set<string>()
    for (const it of all) {
      if (getStageType(it.tagsJson) === 'work') {
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
  }, [items, today, weekStartYmd, weekEnd, stageStart, stageEnd, holidaySet])

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

      {!items && <Alert severity="info">Laden…</Alert>}

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


