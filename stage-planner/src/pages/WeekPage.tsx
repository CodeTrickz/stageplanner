import { Alert, Box, Button, Paper, Stack, Typography } from '@mui/material'
import { useLiveQuery } from 'dexie-react-hooks'
import { useMemo, useState } from 'react'

import { WeekTimeline } from '../components/WeekTimeline'
import { useSettings } from '../app/settings'
import { useAuth } from '../auth/auth'
import { db, type PlanningItem } from '../db/db'
import { addDays, dateFromYmdLocal, startOfWeekMonday, startOfWeekSunday, yyyyMmDdLocal } from '../utils/date'

export function WeekPage() {
  const [anchor, setAnchor] = useState(() => yyyyMmDdLocal(new Date()))
  const { weekStart, workdayStart, weekViewMode, timeFormat } = useSettings()
  const { user } = useAuth()
  const userId = user?.id

  const weekStartYmd = useMemo(() => {
    const base = dateFromYmdLocal(anchor)
    const start =
      weekViewMode === 'workweek' ? startOfWeekMonday(base) : weekStart === 'sunday' ? startOfWeekSunday(base) : startOfWeekMonday(base)
    return yyyyMmDdLocal(start)
  }, [anchor, weekStart, weekViewMode])
  const dayCount = weekViewMode === 'workweek' ? 5 : 7
  const weekEnd = useMemo(() => yyyyMmDdLocal(addDays(dateFromYmdLocal(weekStartYmd), dayCount - 1)), [weekStartYmd, dayCount])

  const items = useLiveQuery(async () => {
    // lexicographic works for YYYY-MM-DD
    const list = await db.planning.where('[ownerUserId+date]').between([userId, weekStartYmd], [userId, weekEnd], true, true).toArray()
    return list
  }, [userId, weekStartYmd, weekEnd], [])

  const days = useMemo(() => {
    const start = dateFromYmdLocal(weekStartYmd)
    return Array.from({ length: dayCount }).map((_, i) => {
      const d = addDays(start, i)
      const ymd = yyyyMmDdLocal(d)
      const label = d.toLocaleDateString(undefined, { weekday: 'short', day: '2-digit', month: '2-digit' })
      return { ymd, label }
    })
  }, [weekStartYmd, dayCount])

  return (
    <Box sx={{ display: 'grid', gap: { xs: 1.5, sm: 2 } }}>
      <Typography variant="h5" sx={{ fontWeight: 800, fontSize: { xs: '1.125rem', sm: '1.25rem' } }}>
        Week planning
      </Typography>

      <Paper sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Stack direction="column" spacing={{ xs: 1.5, sm: 2 }} sx={{ '@media (min-width:600px)': { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' } }}>
          <Alert severity="info" sx={{ fontSize: { xs: '0.75rem', sm: '0.875rem' } }}>
            Sleep een taak om tijd te verschuiven (5-min stappen) of naar een andere dag.
          </Alert>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ flexWrap: 'wrap', gap: { xs: 0.5, sm: 1 } }}>
            <Button size="small" onClick={() => setAnchor(yyyyMmDdLocal(addDays(dateFromYmdLocal(anchor), -7)))}>← Vorige</Button>
            <Button size="small" onClick={() => setAnchor(yyyyMmDdLocal(new Date()))}>Vandaag</Button>
            <Button size="small" onClick={() => setAnchor(yyyyMmDdLocal(addDays(dateFromYmdLocal(anchor), 7)))}>Volgende →</Button>
          </Stack>
        </Stack>
      </Paper>

      <WeekTimeline
        weekDays={days}
        items={(items ?? [])
          .filter((x) => typeof x.id === 'number')
          .map((it) => ({
            id: it.id as number,
            date: it.date,
            start: it.start,
            end: it.end,
            title: it.title,
            priority: it.priority ?? 'medium',
            status: it.status ?? 'todo',
          }))}
        initialScrollM={(() => {
          const [hh, mm] = String(workdayStart || '08:00')
            .split(':')
            .map((x) => Number(x))
          return (hh ?? 8) * 60 + (mm ?? 0)
        })()}
        onSelect={(it) => {
          // quick open: jump to planning day with query
          window.location.href = `/planning?date=${encodeURIComponent(it.date)}`
        }}
        onMove={async (it, next) => {
          await db.planning.update(Number(it.id), { ...next, updatedAt: Date.now() } as Partial<PlanningItem>)
        }}
        timeFormat={timeFormat}
      />
    </Box>
  )
}



