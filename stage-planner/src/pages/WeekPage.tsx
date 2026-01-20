import { Alert, Box, Button, Paper, Stack, Typography } from '@mui/material'
import { useEffect, useMemo, useState } from 'react'

import { WeekTimeline } from '../components/WeekTimeline'
import { useSettings } from '../app/settings'
import { apiFetch, useApiToken } from '../api/client'
import { addDays, dateFromYmdLocal, startOfWeekMonday, startOfWeekSunday, yyyyMmDdLocal } from '../utils/date'
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
}

export function WeekPage() {
  const [anchor, setAnchor] = useState(() => yyyyMmDdLocal(new Date()))
  const { weekStart, workdayStart, weekViewMode, timeFormat } = useSettings()
  const token = useApiToken()
  const { currentWorkspace } = useWorkspace()
  const [items, setItems] = useState<ServerPlanningItem[]>([])
  const [refreshTick, setRefreshTick] = useState(0)

  useWorkspaceEvents((evt) => {
    if (evt.type === 'planning') setRefreshTick((v) => v + 1)
  })

  const weekStartYmd = useMemo(() => {
    const base = dateFromYmdLocal(anchor)
    const start =
      weekViewMode === 'workweek' ? startOfWeekMonday(base) : weekStart === 'sunday' ? startOfWeekSunday(base) : startOfWeekMonday(base)
    return yyyyMmDdLocal(start)
  }, [anchor, weekStart, weekViewMode])
  const dayCount = weekViewMode === 'workweek' ? 5 : 7
  const weekEnd = useMemo(() => yyyyMmDdLocal(addDays(dateFromYmdLocal(weekStartYmd), dayCount - 1)), [weekStartYmd, dayCount])

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

  const itemsForWeek = useMemo(() => {
    return items.filter((it) => it.date >= weekStartYmd && it.date <= weekEnd)
  }, [items, weekStartYmd, weekEnd])

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
        items={itemsForWeek.map((it) => ({
          id: it.id,
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
          const itemId = String(it.id)
          if (!token || !currentWorkspace?.id) return
          const current = items.find((p) => p.id === itemId)
          if (!current) return
          setItems((prev) => prev.map((p) => (p.id === itemId ? { ...p, ...next } : p)))
          try {
            await apiFetch(`/planning?workspaceId=${encodeURIComponent(currentWorkspace.id)}`, {
              method: 'POST',
              token: token || undefined,
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({
                id: itemId,
                date: next.date,
                start: next.start,
                end: next.end,
                title: current.title,
                priority: current.priority,
                status: current.status,
                workspaceId: currentWorkspace.id,
              }),
            })
          } catch {
            // ignore (offline etc)
          }
        }}
        timeFormat={timeFormat}
      />
    </Box>
  )
}



