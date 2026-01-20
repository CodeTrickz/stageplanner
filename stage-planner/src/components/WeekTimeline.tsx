import { DndContext, type DragEndEvent } from '@dnd-kit/core'
import { CSS } from '@dnd-kit/utilities'
import { useDraggable, useDroppable } from '@dnd-kit/core'
import { Box, Paper, Typography } from '@mui/material'
import { useEffect, useMemo, useRef } from 'react'
export type WeekTimelineItem = {
  id: string | number
  date: string
  start: string
  end: string
  title: string
  priority: 'low' | 'medium' | 'high'
  status: 'todo' | 'in_progress' | 'done'
}
import { formatTimeRange, minutesToTime } from '../utils/date'

function timeToMinutes(t: string) {
  const [hh, mm] = t.split(':').map((x) => Number(x))
  return (hh ?? 0) * 60 + (mm ?? 0)
}

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n))
}

function roundTo5(m: number) {
  return Math.round(m / 5) * 5
}

type LayoutItem = {
  item: WeekTimelineItem
  startM: number
  endM: number
  col: number
  colCount: number
}

function computeOverlapLayout(items: WeekTimelineItem[]): LayoutItem[] {
  const sorted = items
    .slice()
    .sort((a, b) => (a.start + a.end).localeCompare(b.start + b.end))
    .map((it) => ({ item: it, startM: timeToMinutes(it.start), endM: timeToMinutes(it.end) }))

  const out: LayoutItem[] = []
  let group: typeof sorted = []
  let groupEnd = -1

  function flush() {
    if (!group.length) return
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
    for (const p of placed) out.push({ item: p.item, startM: p.startM, endM: p.endM, col: p.col, colCount })
    group = []
    groupEnd = -1
  }

  for (const it of sorted) {
    if (!group.length) {
      group = [it]
      groupEnd = it.endM
      continue
    }
    if (it.startM < groupEnd) {
      group.push(it)
      groupEnd = Math.max(groupEnd, it.endM)
    } else {
      flush()
      group = [it]
      groupEnd = it.endM
    }
  }
  flush()
  return out
}

function DraggableItem({
  li,
  labelWidth,
  onClick,
  timeFormat,
}: {
  li: LayoutItem
  labelWidth: number
  onClick: () => void
  timeFormat?: '24h' | '12h'
}) {
  const it = li.item
  const id = `item-${it.id}`
  const { attributes, listeners, setNodeRef, transform, isDragging } = useDraggable({ id })
  const top = li.startM
  const height = Math.max(24, li.endM - li.startM)
  const avail = `calc(100% - ${labelWidth + 8}px)`
  const widthCalc = `calc((${avail}) / ${li.colCount} - 6px)`
  const leftCalc = `calc(${labelWidth}px + (${avail}) * ${li.col} / ${li.colCount})`

  const bg =
    it.status === 'done'
      ? 'success.main'
      : it.priority === 'high'
        ? 'error.main'
        : it.priority === 'low'
          ? 'grey.600'
          : 'primary.main'

  return (
    <Box
      ref={setNodeRef}
      onClick={onClick}
      sx={{
        position: 'absolute',
        left: leftCalc,
        width: widthCalc,
        top,
        height,
        px: 1,
        py: 0.5,
        borderRadius: 2,
        bgcolor: bg,
        color: 'primary.contrastText',
        cursor: 'grab',
        boxShadow: isDragging ? 6 : 1,
        opacity: isDragging ? 0.9 : 1,
        overflow: 'hidden',
        transform: transform ? CSS.Translate.toString(transform) : undefined,
        userSelect: 'none',
        textShadow: '0 1px 2px rgba(0,0,0,0.45)',
      }}
      {...listeners}
      {...attributes}
    >
      <Typography variant="caption" sx={{ opacity: 0.9, fontSize: '0.7rem', lineHeight: 1.1 }}>
        {formatTimeRange(it.start, it.end, { format: timeFormat ?? '24h' })}
      </Typography>
      <Typography
        sx={{ fontWeight: 800, lineHeight: 1.2, fontSize: '0.78rem' }}
        noWrap
        title={it.title}
      >
        {it.title}
      </Typography>
    </Box>
  )
}

function DayColumn({
  ymd,
  label,
  items,
  onSelect,
  initialScrollM,
  timeFormat,
  showHourLabels,
}: {
  ymd: string
  label: string
  items: WeekTimelineItem[]
  onSelect: (it: WeekTimelineItem) => void
  initialScrollM: number
  timeFormat?: '24h' | '12h'
  showHourLabels: boolean
}) {
  const { setNodeRef, isOver } = useDroppable({ id: `day-${ymd}` })
  const labelWidth = showHourLabels ? 36 : 10
  const layout = computeOverlapLayout(items)
  const scrollRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    // keep a bit of context above
    const top = Math.max(0, initialScrollM - 60)
    el.scrollTop = top
  }, [initialScrollM])

  const nowLineTop = useMemo(() => {
    const today = new Date()
    const todayYmd = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`
    if (ymd !== todayYmd) return null
    return today.getHours() * 60 + today.getMinutes()
  }, [ymd])

  return (
    <Paper
      ref={setNodeRef}
      variant="outlined"
      sx={{
        p: 0.75,
        minWidth: 0,
        flex: 1,
        width: '100%',
        bgcolor: isOver ? 'action.hover' : 'background.paper',
      }}
    >
      <Typography sx={{ fontWeight: 900, mb: 1, fontSize: '0.85rem' }} noWrap>
        {label}
      </Typography>
      <Box ref={scrollRef} sx={{ height: 640, overflowY: 'auto', position: 'relative' }}>
        <Box sx={{ position: 'relative', height: 24 * 60 }}>
          {Array.from({ length: 25 }).map((_, h) => {
            const top = h * 60
            const hourLabel =
              timeFormat === '12h'
                ? h === 0
                  ? '12A'
                  : h < 12
                    ? `${h}A`
                    : h === 12
                      ? '12P'
                      : `${h - 12}P`
                : String(h).padStart(2, '0')
            return (
              <Box key={h} sx={{ position: 'absolute', left: 0, right: 0, top }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <Box sx={{ width: labelWidth, pr: 0.5 }}>
                    {showHourLabels && (
                      <Typography variant="caption" color="text.secondary">
                        {hourLabel}
                      </Typography>
                    )}
                  </Box>
                  <Box sx={{ flex: 1, height: 1, bgcolor: 'divider' }} />
                </Box>
              </Box>
            )
          })}

          {typeof nowLineTop === 'number' && (
            <Box sx={{ position: 'absolute', left: 0, right: 0, top: nowLineTop, pointerEvents: 'none' }}>
              <Box sx={{ ml: `${labelWidth}px`, height: 2, bgcolor: 'warning.main', opacity: 0.8 }} />
            </Box>
          )}

          {layout.map((li) => (
            <DraggableItem
              key={li.item.id}
              li={li}
              labelWidth={labelWidth}
              onClick={() => onSelect(li.item)}
              timeFormat={timeFormat}
            />
          ))}
        </Box>
      </Box>
    </Paper>
  )
}

export function WeekTimeline({
  weekDays,
  items,
  onSelect,
  onMove,
  initialScrollM,
  timeFormat,
}: {
  weekDays: Array<{ ymd: string; label: string }>
  items: WeekTimelineItem[]
  onSelect: (it: WeekTimelineItem) => void
  onMove: (it: WeekTimelineItem, next: { date: string; start: string; end: string }) => Promise<void>
  initialScrollM?: number
  timeFormat?: '24h' | '12h'
}) {
  const byDate = new Map<string, WeekTimelineItem[]>()
  for (const it of items) {
    const arr = byDate.get(it.date) ?? []
    arr.push(it)
    byDate.set(it.date, arr)
  }

  function findItem(activeId: string) {
    const id = String(activeId).replace('item-', '')
    return items.find((x) => String(x.id) === id)
  }

  async function onDragEnd(ev: DragEndEvent) {
    const it = findItem(String(ev.active.id))
    if (!it) return
    const overId = ev.over?.id ? String(ev.over.id) : ''
    const overDay = overId.startsWith('day-') ? overId.slice(4) : it.date

    const startM = timeToMinutes(it.start)
    const endM = timeToMinutes(it.end)
    const duration = Math.max(5, endM - startM)
    const deltaM = roundTo5(ev.delta.y)
    const nextStartM = clamp(startM + deltaM, 0, 24 * 60 - duration)
    const nextEndM = nextStartM + duration

    const next = { date: overDay, start: minutesToTime(nextStartM), end: minutesToTime(nextEndM) }
    if (next.date === it.date && next.start === it.start && next.end === it.end) return
    await onMove(it, next)
  }

  return (
    <DndContext onDragEnd={onDragEnd}>
      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: 'repeat(7, minmax(0, 1fr))',
          gap: 1,
          overflowX: 'hidden',
          pb: 1,
        }}
      >
        {weekDays.map((d, idx) => (
          <DayColumn
            key={d.ymd}
            ymd={d.ymd}
            label={d.label}
            items={(byDate.get(d.ymd) ?? []).sort((a, b) => (a.start + a.end).localeCompare(b.start + b.end))}
            onSelect={onSelect}
            initialScrollM={initialScrollM ?? 8 * 60}
            timeFormat={timeFormat}
            showHourLabels={idx === 0}
          />
        ))}
      </Box>
    </DndContext>
  )
}




