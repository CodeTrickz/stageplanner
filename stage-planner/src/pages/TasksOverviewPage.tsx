import EditOutlinedIcon from '@mui/icons-material/EditOutlined'
import SearchIcon from '@mui/icons-material/Search'
import {
  Box,
  Chip,
  IconButton,
  InputAdornment,
  MenuItem,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { useLiveQuery } from 'dexie-react-hooks'
import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/auth'
import { db, type PlanningItem } from '../db/db'

export function TasksOverviewPage() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const userId = user?.id
  const [q, setQ] = useState('')
  const [priority, setPriority] = useState<'all' | PlanningItem['priority']>('all')
  const [status, setStatus] = useState<'all' | PlanningItem['status']>('all')

  const items = useLiveQuery(async () => {
    if (!userId) return []
    const list = await db.planning.where('ownerUserId').equals(userId).toArray()
    // date asc, time asc
    return list.sort((a, b) => (a.date + a.start).localeCompare(b.date + b.start))
  }, [userId])

  const filtered = useMemo(() => {
    if (!items) return []
    const qq = q.trim().toLowerCase()
    return items.filter((it) => {
      if (priority !== 'all' && it.priority !== priority) return false
      if (status !== 'all' && it.status !== status) return false
      if (!qq) return true
      const hay = `${it.title} ${it.notes ?? ''} ${it.date} ${it.start}-${it.end}`.toLowerCase()
      return hay.includes(qq)
    })
  }, [items, q, priority, status])

  const grouped = useMemo(() => {
    const map = new Map<string, PlanningItem[]>()
    for (const it of filtered) {
      const arr = map.get(it.date) ?? []
      arr.push(it)
      map.set(it.date, arr)
    }
    return Array.from(map.entries())
  }, [filtered])

  return (
    <Box sx={{ display: 'grid', gap: { xs: 1.5, sm: 2 } }}>
      <Typography variant="h5" sx={{ fontWeight: 800, fontSize: { xs: '1.125rem', sm: '1.25rem' } }}>
        Taken-overzicht
      </Typography>

      <Paper sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Stack direction="column" spacing={{ xs: 1.5, sm: 2 }} sx={{ '@media (min-width:900px)': { flexDirection: 'row', alignItems: 'center' } }}>
          <TextField
            fullWidth
            label="Zoeken"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            size="small"
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
          />

          <TextField
            select
            label="Prioriteit"
            value={priority}
            onChange={(e) => setPriority(e.target.value as 'all' | PlanningItem['priority'])}
            size="small"
            sx={{ width: { xs: '100%', md: 'auto' }, minWidth: { xs: '100%', md: 160 } }}
          >
            <MenuItem value="all">Alles</MenuItem>
            <MenuItem value="low">Low</MenuItem>
            <MenuItem value="medium">Medium</MenuItem>
            <MenuItem value="high">High</MenuItem>
          </TextField>

          <TextField
            select
            label="Status"
            value={status}
            onChange={(e) => setStatus(e.target.value as 'all' | PlanningItem['status'])}
            size="small"
            sx={{ width: { xs: '100%', md: 'auto' }, minWidth: { xs: '100%', md: 180 } }}
          >
            <MenuItem value="all">Alles</MenuItem>
            <MenuItem value="todo">Todo</MenuItem>
            <MenuItem value="in_progress">In progress</MenuItem>
            <MenuItem value="done">Done</MenuItem>
          </TextField>
        </Stack>
      </Paper>

      {grouped.map(([date, list]) => (
        <Paper key={date} variant="outlined" sx={{ p: 2 }}>
          <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
            <Typography sx={{ fontWeight: 900 }}>{date}</Typography>
            <Chip size="small" label={list.length} />
          </Stack>
          <Box sx={{ display: 'grid', gap: 1, mt: 1 }}>
            {list.map((it) => (
              <Paper
                key={it.id}
                variant="outlined"
                sx={{ p: 1.5, display: 'flex', gap: 2, alignItems: 'center' }}
              >
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Typography sx={{ fontWeight: 800 }} noWrap>
                    {it.start} – {it.end} • {it.title}
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
                <IconButton
                  aria-label="Open in planning"
                  onClick={() => navigate(`/planning?date=${encodeURIComponent(it.date)}`)}
                >
                  <EditOutlinedIcon />
                </IconButton>
              </Paper>
            ))}
          </Box>
        </Paper>
      ))}
    </Box>
  )
}


