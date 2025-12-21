import LaunchIcon from '@mui/icons-material/Launch'
import { Alert, Box, Button, Chip, Divider, IconButton, Paper, Stack, Typography } from '@mui/material'
import { useLiveQuery } from 'dexie-react-hooks'
import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useSettings } from '../app/settings'
import { useAuth } from '../auth/auth'
import { db, type PlanningItem } from '../db/db'
import { addDays, formatTimeRange, startOfWeekMonday, startOfWeekSunday, yyyyMmDdLocal } from '../utils/date'

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
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography sx={{ fontWeight: 900 }}>{title}</Typography>
          <Chip size="small" label={items.length} />
        </Stack>
        <Button size="small" onClick={onOpenAll}>
          Bekijk alles
        </Button>
      </Stack>
      <Divider sx={{ my: 1.5 }} />
      {top.length === 0 ? (
        <Alert severity="info">Geen items.</Alert>
      ) : (
        <Stack spacing={1}>
          {top.map((it) => (
            <Paper key={it.id} variant="outlined" sx={{ p: 1.25 }}>
              <Stack direction="row" spacing={1} alignItems="center">
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Typography sx={{ fontWeight: 800 }} noWrap>
                    {it.date} {formatTimeRange(it.start, it.end, { format: timeFormat })} • {it.title}
                  </Typography>
                  {it.notes && (
                    <Typography variant="body2" color="text.secondary" noWrap>
                      {it.notes}
                    </Typography>
                  )}
                </Box>
                <Chip
                  size="small"
                  label={it.priority === 'high' ? 'High' : it.priority === 'low' ? 'Low' : 'Medium'}
                  color={it.priority === 'high' ? 'error' : it.priority === 'low' ? 'default' : 'primary'}
                  variant={it.priority === 'low' ? 'outlined' : 'filled'}
                />
                <Chip
                  size="small"
                  label={it.status === 'done' ? 'Done' : it.status === 'in_progress' ? 'In progress' : 'Todo'}
                  color={it.status === 'done' ? 'success' : it.status === 'in_progress' ? 'warning' : 'default'}
                  variant="outlined"
                />
                <IconButton aria-label="Open" onClick={() => onOpenItem(it)}>
                  <LaunchIcon />
                </IconButton>
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
  const { weekStart, timeFormat } = useSettings()
  const { user } = useAuth()
  const userId = user?.id
  const items = useLiveQuery(async () => {
    const list = await db.planning.where('ownerUserId').equals(userId).toArray()
    return list.sort(byDateTime)
  }, [userId])

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

    return { todayItems, weekItems, highPriority, overdue, inProgress }
  }, [items, today, weekStartYmd, weekEnd])

  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }} justifyContent="space-between">
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800 }}>
            Dashboard
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Vandaag: <b>{today}</b> • Week: <b>{weekStartYmd}</b> – <b>{weekEnd}</b>
          </Typography>
        </Box>
        <Button variant="outlined" onClick={() => nav('/taken')}>
          Naar taken-overzicht
        </Button>
      </Stack>

      {!items && <Alert severity="info">Laden…</Alert>}

      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' }, gap: 2 }}>
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


