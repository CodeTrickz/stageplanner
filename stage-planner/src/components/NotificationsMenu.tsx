import NotificationsIcon from '@mui/icons-material/Notifications'
import {
  Badge,
  Box,
  Button,
  Divider,
  IconButton,
  ListItemText,
  Menu,
  MenuItem,
  Typography,
} from '@mui/material'
import { useCallback, useEffect, useState } from 'react'
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

export function NotificationsMenu() {
  const token = useApiToken()
  const { currentWorkspace } = useWorkspace()
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null)
  const [items, setItems] = useState<NotificationItem[]>([])
  const [unreadCount, setUnreadCount] = useState(0)
  const [loading, setLoading] = useState(false)
  const [refreshTick, setRefreshTick] = useState(0)

  useWorkspaceEvents((evt) => {
    if (evt.type === 'notifications') setRefreshTick((v) => v + 1)
  })

  const open = Boolean(anchorEl)

  const load = useCallback(async () => {
    if (!token || !currentWorkspace?.id) return
    setLoading(true)
    try {
      const result = await apiFetch(
        `/notifications?workspaceId=${encodeURIComponent(String(currentWorkspace.id))}`,
        { token: token || undefined },
      )
      setItems((result.items || []) as NotificationItem[])
      setUnreadCount(Number(result.unreadCount || 0))
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [token, currentWorkspace?.id])

  useEffect(() => {
    if (!token || !currentWorkspace?.id) return
    void load()
  }, [token, currentWorkspace?.id, refreshTick, load])

  async function markRead(ids: string[]) {
    if (!token || !currentWorkspace?.id) return
    if (ids.length === 0) return
    try {
      await apiFetch('/notifications/read', {
        method: 'POST',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ids, workspaceId: String(currentWorkspace.id) }),
      })
      setItems((prev) => prev.map((n) => (ids.includes(n.id) ? { ...n, readAt: Date.now() } : n)))
      setUnreadCount((prev) => Math.max(0, prev - ids.length))
    } catch {
      // ignore
    }
  }

  async function markAllRead() {
    if (!token || !currentWorkspace?.id) return
    try {
      await apiFetch('/notifications/read', {
        method: 'POST',
        token: token || undefined,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ workspaceId: String(currentWorkspace.id) }),
      })
      setItems((prev) => prev.map((n) => ({ ...n, readAt: n.readAt ?? Date.now() })))
      setUnreadCount(0)
    } catch {
      // ignore
    }
  }

  return (
    <>
      <IconButton
        aria-label="Notificaties"
        onClick={(e) => {
          setAnchorEl(e.currentTarget)
          void load()
        }}
        size="medium"
        sx={{ ml: { xs: 0.5, sm: 1 } }}
        disabled={!currentWorkspace?.id}
      >
        <Badge color="error" badgeContent={unreadCount > 99 ? '99+' : unreadCount} invisible={unreadCount === 0}>
          <NotificationsIcon />
        </Badge>
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={() => setAnchorEl(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
        PaperProps={{ sx: { width: 360, maxWidth: '90vw' } }}
      >
        <Box sx={{ px: 2, py: 1, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Typography sx={{ fontWeight: 700 }}>Notificaties</Typography>
          <Button size="small" onClick={markAllRead} disabled={items.length === 0}>
            Alles gelezen
          </Button>
        </Box>
        <Divider />
        {loading && <MenuItem disabled>Bezig met laden…</MenuItem>}
        {!loading && items.length === 0 && <MenuItem disabled>Geen notificaties</MenuItem>}
        {!loading &&
          items.map((n) => (
            <MenuItem
              key={n.id}
              onClick={() => markRead([n.id])}
              sx={{ alignItems: 'flex-start', whiteSpace: 'normal' }}
            >
              <ListItemText
                primary={
                  <Typography sx={{ fontWeight: n.readAt ? 500 : 700 }}>{n.title}</Typography>
                }
                secondary={
                  <>
                    <Typography variant="body2" color="text.secondary">
                      {n.body}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {new Date(n.createdAt).toLocaleString()}
                    </Typography>
                  </>
                }
              />
            </MenuItem>
          ))}
      </Menu>
    </>
  )
}
