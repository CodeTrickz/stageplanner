import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  IconButton,
  LinearProgress,
  List,
  ListItemButton,
  ListItemText,
  MenuItem,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import InfoIcon from '@mui/icons-material/InfoOutlined'
import { useEffect, useMemo, useState } from 'react'
import { apiFetch, useApiToken } from '../api/client'
import { useWorkspace } from '../hooks/useWorkspace'
import { useWorkspaceEvents } from '../hooks/useWorkspaceEvents'

type NotificationItem = {
  id: string
  workspaceId: string
  type: 'deadline_overdue' | 'deadline_soon'
  title: string
  body: string
  dueAt: number
  createdAt: number
  readAt: number | null
}

type FilterMode = 'all' | 'unread'

export function NotificationsPage() {
  const token = useApiToken()
  const { currentWorkspace } = useWorkspace()
  const [items, setItems] = useState<NotificationItem[]>([])
  const [unreadCount, setUnreadCount] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [refreshTick, setRefreshTick] = useState(0)
  const [filter, setFilter] = useState<FilterMode>('all')
  const [selected, setSelected] = useState<NotificationItem | null>(null)

  useWorkspaceEvents((evt) => {
    if (evt.type === 'notifications') setRefreshTick((v) => v + 1)
  })

  const canLoad = !!token && !!currentWorkspace?.id

  const load = async () => {
    if (!canLoad) return
    setLoading(true)
    setError(null)
    try {
      const result = await apiFetch(
        `/notifications?workspaceId=${encodeURIComponent(String(currentWorkspace!.id))}&limit=200`,
        { token: token || undefined },
      )
      const list = (result.items || []) as NotificationItem[]
      setItems(list)
      setUnreadCount(Number(result.unreadCount || 0))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Kon notificaties niet laden.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!canLoad) return
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canLoad, refreshTick])

  async function markRead(ids: string[]) {
    if (!canLoad || ids.length === 0) return
    try {
      await apiFetch('/notifications/read', {
        method: 'POST',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ids, workspaceId: String(currentWorkspace!.id) }),
      })
      const now = Date.now()
      setItems((prev) => prev.map((n) => (ids.includes(n.id) ? { ...n, readAt: n.readAt ?? now } : n)))
      setUnreadCount((prev) => Math.max(0, prev - ids.length))
      setSelected((prev) => (prev && ids.includes(prev.id) ? { ...prev, readAt: prev.readAt ?? now } : prev))
    } catch {
      // ignore for now
    }
  }

  async function markAllRead() {
    if (!canLoad || items.length === 0) return
    try {
      await apiFetch('/notifications/read', {
        method: 'POST',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ workspaceId: String(currentWorkspace!.id) }),
      })
      const now = Date.now()
      setItems((prev) => prev.map((n) => ({ ...n, readAt: n.readAt ?? now })))
      setUnreadCount(0)
      setSelected((prev) => (prev ? { ...prev, readAt: prev.readAt ?? now } : prev))
    } catch {
      // ignore
    }
  }

  async function deleteNotifications(ids: string[]) {
    if (!canLoad || ids.length === 0) return
    try {
      await apiFetch('/notifications/delete', {
        method: 'POST',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ids }),
      })
      setItems((prev) => prev.filter((n) => !ids.includes(n.id)))
      setUnreadCount((prev) => {
        const removedUnread = items.filter((n) => ids.includes(n.id) && !n.readAt).length
        return Math.max(0, prev - removedUnread)
      })
      setSelected((prev) => (prev && ids.includes(prev.id) ? null : prev))
    } catch {
      // ignore for now
    }
  }

  async function deleteAllRead() {
    const readIds = items.filter((n) => !!n.readAt).map((n) => n.id)
    if (readIds.length === 0) return
    await deleteNotifications(readIds)
  }

  const filteredItems = useMemo(() => {
    if (filter === 'unread') return items.filter((n) => !n.readAt)
    return items
  }, [items, filter])

  function formatType(n: NotificationItem) {
    if (n.type === 'deadline_overdue') return 'Deadline overschreden'
    if (n.type === 'deadline_soon') return 'Deadline nadert'
    return n.type
  }

  function formatDue(dueAt: number) {
    if (!Number.isFinite(dueAt)) return ''
    return new Date(dueAt).toLocaleString()
  }

  return (
    <Box sx={{ display: 'grid', gap: { xs: 1.5, sm: 2 } }}>
      <Typography variant="h5" sx={{ fontWeight: 800, fontSize: { xs: '1.125rem', sm: '1.25rem' } }}>
        Notificaties
      </Typography>
      <Typography variant="body2" color="text.secondary">
        Bekijk en beheer deadline-notificaties voor je huidige workspace. Notificaties worden automatisch aangemaakt voor
        items waarvan de deadline bijna bereikt is of overschreden is.
      </Typography>

      <Paper sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          spacing={{ xs: 1, sm: 2 }}
          alignItems={{ xs: 'flex-start', sm: 'center' }}
          justifyContent="space-between"
        >
          <Stack direction="row" spacing={1} alignItems="center">
            <Chip
              size="small"
              color={unreadCount > 0 ? 'error' : 'default'}
              label={unreadCount > 0 ? `${unreadCount} ongelezen` : 'Alles gelezen'}
            />
            <TextField
              select
              size="small"
              label="Filter"
              value={filter}
              onChange={(e) => setFilter(e.target.value as FilterMode)}
              sx={{ minWidth: 160 }}
            >
              <MenuItem value="all">Alle notificaties</MenuItem>
              <MenuItem value="unread">Alleen ongelezen</MenuItem>
            </TextField>
          </Stack>
          <Stack direction="row" spacing={1}>
            <Button variant="outlined" size="small" onClick={() => void load()} disabled={!canLoad || loading}>
              Vernieuwen
            </Button>
            <Button
              variant="contained"
              size="small"
              color="primary"
              onClick={() => void markAllRead()}
              disabled={!canLoad || items.length === 0 || unreadCount === 0}
            >
              Alles gelezen
            </Button>
            <Button
              variant="outlined"
              size="small"
              color="error"
              onClick={() => void deleteAllRead()}
              disabled={!canLoad || items.every((n) => !n.readAt)}
            >
              Verwijder alle gelezen
            </Button>
          </Stack>
        </Stack>
        {!canLoad && (
          <Alert severity="info" sx={{ mt: 2 }}>
            Selecteer eerst een workspace om notificaties te zien.
          </Alert>
        )}
        {loading && <LinearProgress sx={{ mt: 2 }} />}
        {error && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {error}
          </Alert>
        )}

        {!loading && filteredItems.length === 0 && canLoad && !error && (
          <Alert severity="info" sx={{ mt: 2 }}>
            Geen notificaties gevonden voor deze workspace.
          </Alert>
        )}

        {filteredItems.length > 0 && (
          <Box sx={{ mt: 2 }}>
            <List dense disablePadding>
              {filteredItems.map((n) => (
                <ListItemButton
                  key={n.id}
                  selected={selected?.id === n.id}
                  onClick={() => setSelected(n)}
                  sx={{
                    alignItems: 'flex-start',
                    py: 1,
                    '&.Mui-selected': { bgcolor: 'action.selected' },
                  }}
                >
                  <ListItemText
                    primary={
                      <Stack direction="row" alignItems="center" spacing={1}>
                        <Typography sx={{ fontWeight: n.readAt ? 500 : 700 }}>{n.title}</Typography>
                        <Chip
                          size="small"
                          label={formatType(n)}
                          color={n.type === 'deadline_overdue' ? 'error' : 'warning'}
                          variant="outlined"
                        />
                        {!n.readAt && (
                          <Chip size="small" label="Ongelezen" color="primary" variant="filled" sx={{ ml: 0.5 }} />
                        )}
                      </Stack>
                    }
                    secondary={
                      <Stack spacing={0.25} sx={{ mt: 0.5 }}>
                        <Typography
                          variant="body2"
                          color="text.secondary"
                          sx={{ display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}
                        >
                          {n.body}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Aangemaakt: {new Date(n.createdAt).toLocaleString()}
                          {' • '}Deadline: {formatDue(n.dueAt)}
                        </Typography>
                      </Stack>
                    }
                  />
                  {!n.readAt && (
                    <IconButton
                      edge="end"
                      aria-label="Markeer als gelezen"
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation()
                        void markRead([n.id])
                      }}
                    >
                      <InfoIcon fontSize="small" />
                    </IconButton>
                  )}
                </ListItemButton>
              ))}
            </List>
          </Box>
        )}
      </Paper>

      {selected && (
        <Paper sx={{ p: { xs: 1.5, sm: 2 } }}>
          <Stack spacing={1.5}>
            <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography variant="h6" sx={{ fontWeight: 800, fontSize: { xs: '1rem', sm: '1.125rem' } }}>
                  {selected.title}
                </Typography>
                <Chip
                  size="small"
                  label={formatType(selected)}
                  color={selected.type === 'deadline_overdue' ? 'error' : 'warning'}
                  variant="outlined"
                />
                {!selected.readAt && <Chip size="small" label="Ongelezen" color="primary" />}
              </Stack>
              <Stack direction="row" spacing={1}>
                {!selected.readAt && (
                  <Button variant="contained" size="small" onClick={() => void markRead([selected.id])}>
                    Markeer als gelezen
                  </Button>
                )}
                <Button
                  variant="outlined"
                  size="small"
                  color="error"
                  onClick={() => void deleteNotifications([selected.id])}
                >
                  Verwijder notificatie
                </Button>
              </Stack>
            </Stack>
            <Divider />
            <Typography variant="body2" color="text.secondary">
              Deadline: {formatDue(selected.dueAt)}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Aangemaakt: {new Date(selected.createdAt).toLocaleString()}
            </Typography>
            <Typography sx={{ whiteSpace: 'pre-wrap', mt: 1 }}>{selected.body}</Typography>
          </Stack>
        </Paper>
      )}
    </Box>
  )
}

