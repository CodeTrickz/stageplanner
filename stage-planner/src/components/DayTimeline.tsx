import { Box, Paper, Typography } from '@mui/material'
import { formatTimeRange } from '../utils/date'

function timeToMinutes(t: string) {
  const [hh, mm] = t.split(':').map((x) => Number(x))
  return (hh ?? 0) * 60 + (mm ?? 0)
}

type LayoutItem = {
  item: TimelineItem
  startM: number
  endM: number
  col: number
  colCount: number
}

export type TimelineItem = {
  id: string | number
  start: string
  end: string
  title: string
  priority: 'low' | 'medium' | 'high'
  status: 'todo' | 'in_progress' | 'done'
}

function computeOverlapLayout(items: TimelineItem[]): LayoutItem[] {
  const sorted = items
    .slice()
    .sort((a, b) => (a.start + a.end).localeCompare(b.start + b.end))
    .map((it) => ({ item: it, startM: timeToMinutes(it.start), endM: timeToMinutes(it.end) }))

  const out: LayoutItem[] = []

  // Build overlap groups
  let group: typeof sorted = []
  let groupEnd = -1
  function flushGroup() {
    if (group.length === 0) return

    // interval partitioning within group
    const colEnds: number[] = []
    const placed = group.map((g) => {
      let col = colEnds.findIndex((e) => e <= g.startM)
      if (col === -1) {
        col = colEnds.length
        colEnds.push(g.endM)
      } else {
        colEnds[col] = g.endM
      }
      return { ...g, col }
    })
    const colCount = colEnds.length

    for (const p of placed) {
      out.push({ item: p.item, startM: p.startM, endM: p.endM, col: p.col, colCount })
    }
    group = []
    groupEnd = -1
  }

  for (const it of sorted) {
    if (group.length === 0) {
      group = [it]
      groupEnd = it.endM
      continue
    }
    if (it.startM < groupEnd) {
      group.push(it)
      groupEnd = Math.max(groupEnd, it.endM)
    } else {
      flushGroup()
      group = [it]
      groupEnd = it.endM
    }
  }
  flushGroup()

  return out
}

export function DayTimeline({
  items,
  onSelect,
  timeFormat,
}: {
  items: TimelineItem[]
  onSelect: (item: TimelineItem) => void
  timeFormat?: '24h' | '12h'
}) {
  const pxPerMinute = 1
  const height = 24 * 60 * pxPerMinute
  const labelWidth = 56
  const layout = computeOverlapLayout(items)

  return (
    <Paper variant="outlined" sx={{ p: 1.5 }}>
      <Typography sx={{ fontWeight: 900, mb: 1 }}>Dag overzicht</Typography>

      <Box sx={{ height: 640, overflowY: 'auto', position: 'relative' }}>
        <Box sx={{ position: 'relative', height }}>
          {/* hour lines */}
          {Array.from({ length: 25 }).map((_, h) => {
            const top = h * 60 * pxPerMinute
            const label = timeFormat === '12h' ? (h === 0 ? '12 AM' : h < 12 ? `${h} AM` : h === 12 ? '12 PM' : `${h - 12} PM`) : `${String(h).padStart(2, '0')}:00`
            return (
              <Box key={h} sx={{ position: 'absolute', left: 0, right: 0, top }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <Box sx={{ width: labelWidth, pr: 1 }}>
                    <Typography variant="caption" color="text.secondary">
                      {label}
                    </Typography>
                  </Box>
                  <Box sx={{ flex: 1, height: 1, bgcolor: 'divider' }} />
                </Box>
              </Box>
            )
          })}

          {/* items */}
          {layout.map((li) => {
            const it = li.item
            const top = li.startM * pxPerMinute
            const itemHeight = Math.max(18, (li.endM - li.startM) * pxPerMinute)
            const bg =
              it.status === 'done'
                ? 'success.main'
                : it.priority === 'high'
                  ? 'error.main'
                  : it.priority === 'low'
                    ? 'grey.600'
                    : 'primary.main'
            const hover =
              it.status === 'done'
                ? 'success.dark'
                : it.priority === 'high'
                  ? 'error.dark'
                  : it.priority === 'low'
                    ? 'grey.800'
                    : 'primary.dark'
            const availableWidth = `calc(100% - ${labelWidth + 8}px)`
            const widthCalc = `calc((${availableWidth}) / ${li.colCount} - 6px)`
            const leftCalc = `calc(${labelWidth}px + (${availableWidth}) * ${li.col} / ${li.colCount})`
            return (
              <Box
                key={it.id}
                onClick={() => onSelect(it)}
                sx={{
                  position: 'absolute',
                  left: leftCalc,
                  width: widthCalc,
                  top,
                  height: itemHeight,
                  px: 1.25,
                  py: 0.75,
                  borderRadius: 2,
                  bgcolor: bg,
                  color: 'primary.contrastText',
                  cursor: 'pointer',
                  boxShadow: 1,
                  overflow: 'hidden',
                  '&:hover': { bgcolor: hover },
                }}
              >
                <Typography variant="caption" sx={{ opacity: 0.9 }}>
                  {formatTimeRange(it.start, it.end, { format: timeFormat ?? '24h' })}
                </Typography>
                <Typography sx={{ fontWeight: 900, lineHeight: 1.2 }} noWrap>
                  {it.title}
                </Typography>
              </Box>
            )
          })}
        </Box>
      </Box>
    </Paper>
  )
}


