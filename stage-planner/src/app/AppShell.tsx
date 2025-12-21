import AttachFileIcon from '@mui/icons-material/AttachFile'
import CalendarMonthIcon from '@mui/icons-material/CalendarMonth'
import DescriptionIcon from '@mui/icons-material/Description'
import DashboardIcon from '@mui/icons-material/Dashboard'
import ListAltIcon from '@mui/icons-material/ListAlt'
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings'
import SettingsIcon from '@mui/icons-material/Settings'
import SearchIcon from '@mui/icons-material/Search'
import MenuIcon from '@mui/icons-material/Menu'
import {
  AppBar,
  Box,
  Button,
  Chip,
  Container,
  Divider,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Tab,
  Tabs,
  Toolbar,
  Typography,
  useMediaQuery,
  useTheme,
} from '@mui/material'
import React from 'react'
import { Link as RouterLink, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/auth'
import { subscribeApiStatus } from '../api/client'
import { useBackendHealth } from '../hooks/useBackendHealth'
import { useOnlineStatus } from '../hooks/useOnlineStatus'
import { GlobalSearchDialog } from '../components/GlobalSearchDialog'

const tabs = [
  { label: 'Dashboard', to: '/dashboard', icon: <DashboardIcon /> },
  { label: 'Planning', to: '/planning', icon: <CalendarMonthIcon /> },
  { label: 'Week', to: '/week', icon: <CalendarMonthIcon /> },
  { label: 'Taken', to: '/taken', icon: <ListAltIcon /> },
  { label: 'Gedeeld', to: '/shared', icon: <ListAltIcon /> },
  { label: 'Bestanden', to: '/bestanden', icon: <AttachFileIcon /> },
  { label: 'Notities / mail', to: '/notities', icon: <DescriptionIcon /> },
  { label: 'Instellingen', to: '/settings', icon: <SettingsIcon /> },
  { label: 'Admin', to: '/admin', icon: <AdminPanelSettingsIcon />, adminOnly: true },
] as const

function tabValueFromPath(pathname: string) {
  const found = tabs.find((t) => pathname === t.to || pathname.startsWith(t.to + '/'))
  return found?.to ?? tabs[0].to
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const { pathname } = useLocation()
  const value = tabValueFromPath(pathname)
  const nav = useNavigate()
  const { user, logout } = useAuth()
  const theme = useTheme()
  const isMobile = useMediaQuery(theme.breakpoints.down('md'))
  const [drawerOpen, setDrawerOpen] = React.useState(false)
  const online = useOnlineStatus()
  const backendOk = useBackendHealth(!!user && online)
  const [api, setApi] = React.useState<{ inFlight: number; lastSuccessAt: number | null; lastErrorAt: number | null }>({
    inFlight: 0,
    lastSuccessAt: null,
    lastErrorAt: null,
  })

  React.useEffect(() => subscribeApiStatus(setApi), [])

  const statusChip = (() => {
    if (!user) return <Chip size="small" label="Local" variant="outlined" />
    if (!online) return <Chip size="small" label="Offline" color="warning" />
    if (backendOk === false) return <Chip size="small" label="Backend offline" color="warning" />
    if (api.inFlight > 0) return <Chip size="small" label="Syncing…" color="info" />
    if (api.lastErrorAt && (!api.lastSuccessAt || api.lastErrorAt > api.lastSuccessAt))
      return <Chip size="small" label="Sync error" color="error" />
    return <Chip size="small" label="Synced" color="success" />
  })()

  const [searchOpen, setSearchOpen] = React.useState(false)

  const isAdmin = !!(user as any)?.isAdmin
  const visibleTabs = tabs.filter((t) => (!(t as any).adminOnly || isAdmin))

  return (
    <Box sx={{ minHeight: '100%', display: 'flex', flexDirection: 'column' }}>
      <AppBar position="sticky" elevation={0} color="inherit">
        <Toolbar sx={{ gap: 1.5 }}>
          {user && isMobile && (
            <IconButton
              edge="start"
              aria-label="Menu"
              onClick={() => setDrawerOpen(true)}
              sx={{ mr: 0.5 }}
            >
              <MenuIcon />
            </IconButton>
          )}
          <Typography variant="h6" sx={{ fontWeight: 800 }}>
            Stage Planner
          </Typography>
          {user && !isMobile && (
            <Tabs
              value={value}
              textColor="primary"
              indicatorColor="primary"
              sx={{ ml: 1 }}
            >
              {visibleTabs.map((t) => (
                  <Tab
                    key={t.to}
                    value={t.to}
                    label={t.label}
                    icon={t.icon}
                    iconPosition="start"
                    component={RouterLink}
                    to={t.to}
                    sx={{ minHeight: 48 }}
                  />
              ))}
            </Tabs>
          )}
          <Box sx={{ flex: 1 }} />
          <Box sx={{ display: { xs: 'none', sm: 'block' } }}>{statusChip}</Box>
          {user && (
            <IconButton aria-label="Zoek" onClick={() => setSearchOpen(true)}>
              <SearchIcon />
            </IconButton>
          )}
          {user ? (
            <Button
              variant="outlined"
              sx={{ display: { xs: 'none', sm: 'inline-flex' } }}
              onClick={() => {
                logout()
                nav('/login')
              }}
            >
              Logout ({user.email})
            </Button>
          ) : (
            <Button variant="contained" component={RouterLink} to="/login">
              Login
            </Button>
          )}
        </Toolbar>
      </AppBar>

      <Drawer
        anchor="left"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        PaperProps={{ sx: { width: 320, maxWidth: '85vw' } }}
      >
        <Box sx={{ p: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 900 }}>
            Stage Planner
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.25 }}>
            {user ? `Ingelogd als ${user.email}` : 'Niet ingelogd'}
          </Typography>
          <Box sx={{ mt: 1 }}>{statusChip}</Box>
        </Box>
        <Divider />
        <List disablePadding>
          {visibleTabs.map((t) => (
            <ListItemButton
              key={t.to}
              selected={value === t.to}
              onClick={() => {
                setDrawerOpen(false)
                nav(t.to)
              }}
            >
              <ListItemIcon sx={{ minWidth: 40 }}>{t.icon}</ListItemIcon>
              <ListItemText primary={t.label} />
            </ListItemButton>
          ))}
        </List>
        <Divider />
        {user ? (
          <Box sx={{ p: 2 }}>
            <Button
              fullWidth
              variant="outlined"
              onClick={() => {
                setDrawerOpen(false)
                logout()
                nav('/login')
              }}
            >
              Logout
            </Button>
          </Box>
        ) : (
          <Box sx={{ p: 2 }}>
            <Button fullWidth variant="contained" onClick={() => nav('/login')}>
              Login
            </Button>
          </Box>
        )}
      </Drawer>

      <Container sx={{ py: { xs: 2, sm: 3 }, flex: 1, px: { xs: 1.5, sm: 2 } }}>{children}</Container>
      <GlobalSearchDialog open={searchOpen} onClose={() => setSearchOpen(false)} />
    </Box>
  )
}


