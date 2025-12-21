import ChevronLeftIcon from '@mui/icons-material/ChevronLeft'
import ChevronRightIcon from '@mui/icons-material/ChevronRight'
import { Box, IconButton, Paper, Stack, Typography } from '@mui/material'
import { dateFromYmdLocal, ymdFromParts } from '../utils/date'

const weekdays = ['Ma', 'Di', 'Wo', 'Do', 'Vr', 'Za', 'Zo'] as const

function startOfMonth(d: Date) {
  return new Date(d.getFullYear(), d.getMonth(), 1)
}

function addMonths(d: Date, delta: number) {
  return new Date(d.getFullYear(), d.getMonth() + delta, 1)
}

function daysInMonth(d: Date) {
  return new Date(d.getFullYear(), d.getMonth() + 1, 0).getDate()
}

function mondayIndex(day0Sunday: number) {
  // JS: 0=Sun..6=Sat -> 0=Mon..6=Sun
  return (day0Sunday + 6) % 7
}

export function MonthCalendar({
  value,
  onChange,
}: {
  value: string // YYYY-MM-DD
  onChange: (ymd: string) => void
}) {
  const selected = dateFromYmdLocal(value)
  const monthStart = startOfMonth(selected)
  const monthDays = daysInMonth(monthStart)
  const startOffset = mondayIndex(monthStart.getDay())

  const cells: Array<{ ymd: string; day: number; inMonth: boolean }> = []
  const y = monthStart.getFullYear()
  const m = monthStart.getMonth()

  // leading empty days (previous month)
  const prevMonth = addMonths(monthStart, -1)
  const prevDays = daysInMonth(prevMonth)
  for (let i = 0; i < startOffset; i++) {
    const day = prevDays - (startOffset - 1 - i)
    cells.push({ ymd: ymdFromParts(prevMonth.getFullYear(), prevMonth.getMonth(), day), day, inMonth: false })
  }
  for (let day = 1; day <= monthDays; day++) {
    cells.push({ ymd: ymdFromParts(y, m, day), day, inMonth: true })
  }
  // trailing to full weeks (42 cells)
  while (cells.length % 7 !== 0) {
    const last = dateFromYmdLocal(cells[cells.length - 1].ymd)
    const next = new Date(last.getFullYear(), last.getMonth(), last.getDate() + 1)
    cells.push({ ymd: ymdFromParts(next.getFullYear(), next.getMonth(), next.getDate()), day: next.getDate(), inMonth: false })
  }
  while (cells.length < 42) {
    const last = dateFromYmdLocal(cells[cells.length - 1].ymd)
    const next = new Date(last.getFullYear(), last.getMonth(), last.getDate() + 1)
    cells.push({ ymd: ymdFromParts(next.getFullYear(), next.getMonth(), next.getDate()), day: next.getDate(), inMonth: false })
  }

  return (
    <Paper variant="outlined" sx={{ p: 1.5 }}>
      <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
        <IconButton aria-label="Vorige maand" onClick={() => onChange(ymdFromParts(addMonths(monthStart, -1).getFullYear(), addMonths(monthStart, -1).getMonth(), 1))}>
          <ChevronLeftIcon />
        </IconButton>
        <Typography sx={{ fontWeight: 900 }}>
          {monthStart.toLocaleDateString(undefined, { month: 'long', year: 'numeric' })}
        </Typography>
        <IconButton aria-label="Volgende maand" onClick={() => onChange(ymdFromParts(addMonths(monthStart, 1).getFullYear(), addMonths(monthStart, 1).getMonth(), 1))}>
          <ChevronRightIcon />
        </IconButton>
      </Stack>

      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 0.5, mt: 1 }}>
        {weekdays.map((w) => (
          <Typography key={w} variant="caption" sx={{ fontWeight: 900, textAlign: 'center' }}>
            {w}
          </Typography>
        ))}
        {cells.map((c) => {
          const isSelected = c.ymd === value
          return (
            <Box
              key={c.ymd}
              onClick={() => onChange(c.ymd)}
              sx={{
                userSelect: 'none',
                cursor: 'pointer',
                borderRadius: 2,
                py: 0.75,
                textAlign: 'center',
                fontWeight: isSelected ? 900 : 600,
                bgcolor: isSelected ? 'primary.main' : 'transparent',
                color: isSelected ? 'primary.contrastText' : c.inMonth ? 'text.primary' : 'text.disabled',
                '&:hover': { bgcolor: isSelected ? 'primary.dark' : 'action.hover' },
              }}
            >
              {c.day}
            </Box>
          )
        })}
      </Box>
    </Paper>
  )
}









