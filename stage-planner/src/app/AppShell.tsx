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
  // Responsive breakpoints: xs (<600px), sm (600-960px), md (960-1280px), lg (1280px+)
  const isMobile = useMediaQuery(theme.breakpoints.down('sm')) // < 600px
  const isTablet = useMediaQuery(theme.breakpoints.between('sm', 'md')) // 600px - 960px
  const isDesktop = useMediaQuery(theme.breakpoints.up('md')) // >= 960px
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

  const isAdmin = !!(user?.isAdmin)
  const visibleTabs = tabs.filter((t) => (!('adminOnly' in t && t.adminOnly) || isAdmin))

  return (
    <Box sx={{ minHeight: '100%', display: 'flex', flexDirection: 'column' }}>
      <AppBar position="sticky" elevation={0} color="inherit">
        <Toolbar 
          sx={{ 
            gap: { xs: 0.5, sm: 1, md: 1.5 }, 
            minHeight: { xs: 56, sm: 64 },
            px: { xs: 1, sm: 1.5, md: 2 }
          }}
        >
          {/* Mobile & Tablet: Menu button */}
          {user && (isMobile || isTablet) && (
            <IconButton
              edge="start"
              aria-label="Menu"
              onClick={() => setDrawerOpen(true)}
              sx={{ mr: { xs: 0.5, sm: 1 } }}
              size={isMobile ? 'small' : 'medium'}
            >
              <MenuIcon />
            </IconButton>
          )}
          
          {/* App title - responsive sizing */}
          <Typography 
            variant="h6" 
            sx={{ 
              fontWeight: 800, 
              fontSize: { xs: '0.875rem', sm: '1rem', md: '1.125rem' },
              flexShrink: 0
            }}
          >
            Planner
          </Typography>
          
          {/* Desktop: Full tabs with labels */}
          {user && isDesktop && (
            <Tabs
              value={value}
              textColor="primary"
              indicatorColor="primary"
              sx={{ 
                ml: { md: 1, lg: 2 },
                minHeight: { md: 48, lg: 64 },
                '& .MuiTab-root': {
                  minHeight: { md: 48, lg: 64 },
                  fontSize: { md: '0.8125rem', lg: '0.875rem' },
                  px: { md: 1.5, lg: 2 },
                }
              }}
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
                />
              ))}
            </Tabs>
          )}
          
          <Box sx={{ flex: 1 }} />
          
          {/* Status chip - hidden on mobile */}
          <Box sx={{ display: { xs: 'none', sm: 'block' } }}>{statusChip}</Box>
          
          {/* Search button */}
          {user && (
            <IconButton 
              aria-label="Zoek" 
              onClick={() => setSearchOpen(true)} 
              size={isMobile ? 'small' : 'medium'}
              sx={{ ml: { xs: 0.5, sm: 1 } }}
            >
              <SearchIcon />
            </IconButton>
          )}
          
          {/* Logout/Login button */}
          {user ? (
            <Button
              variant="outlined"
              size={isMobile ? 'small' : 'medium'}
              sx={{ 
                display: { xs: 'none', sm: 'inline-flex' },
                fontSize: { xs: '0.75rem', sm: '0.8125rem', md: '0.875rem' },
                ml: { xs: 0.5, sm: 1 },
                px: { xs: 1, sm: 1.5, md: 2 }
              }}
              onClick={() => {
                logout()
                nav('/login')
              }}
            >
              {/* Show username on desktop, just "Logout" on tablet */}
              <Box component="span" sx={{ display: { xs: 'none', lg: 'inline' } }}>
                Logout ({user.username })
              </Box>
              <Box component="span" sx={{ display: { xs: 'none', sm: 'inline', lg: 'none' } }}>
                Logout
              </Box>
            </Button>
          ) : (
            <Button 
              variant="contained" 
              component={RouterLink} 
              to="/login" 
              size={isMobile ? 'small' : 'medium'}
              sx={{ 
                fontSize: { xs: '0.75rem', sm: '0.8125rem', md: '0.875rem' },
                px: { xs: 1, sm: 1.5, md: 2 }
              }}
            >
              Login
            </Button>
          )}
        </Toolbar>
      </AppBar>

      <Drawer
        anchor="left"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        PaperProps={{ 
          sx: { 
            width: { xs: '85vw', sm: 300, md: 320 },
            maxWidth: { xs: '85vw', sm: '90vw' }
          } 
        }}
      >
        <Box sx={{ p: { xs: 1.5, sm: 2 } }}>
          <Typography 
            variant="h6" 
            sx={{ 
              fontWeight: 900,
              fontSize: { xs: '1rem', sm: '1.125rem' }
            }}
          >
            Stage Planner
          </Typography>
          <Typography 
            variant="body2" 
            color="text.secondary" 
            sx={{ 
              mt: 0.25,
              fontSize: { xs: '0.75rem', sm: '0.8125rem' }
            }}
          >
            {user ? `Ingelogd als ${user.username || 'User'}` : 'Niet ingelogd'}
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
              sx={{
                py: { xs: 1, sm: 1.25 },
                px: { xs: 1.5, sm: 2 }
              }}
            >
              <ListItemIcon 
                sx={{ 
                  minWidth: { xs: 36, sm: 40 },
                  '& svg': {
                    fontSize: { xs: '1.25rem', sm: '1.5rem' }
                  }
                }}
              >
                {t.icon}
              </ListItemIcon>
              <ListItemText 
                primary={t.label}
                primaryTypographyProps={{
                  fontSize: { xs: '0.875rem', sm: '0.9375rem' },
                  fontWeight: value === t.to ? 700 : 400
                }}
              />
            </ListItemButton>
          ))}
        </List>
        <Divider />
        {user ? (
          <Box sx={{ p: { xs: 1.5, sm: 2 } }}>
            <Button
              fullWidth
              variant="outlined"
              size={isMobile ? 'small' : 'medium'}
              onClick={() => {
                setDrawerOpen(false)
                logout()
                nav('/login')
              }}
              sx={{
                fontSize: { xs: '0.875rem', sm: '0.9375rem' }
              }}
            >
              Logout
            </Button>
          </Box>
        ) : (
          <Box sx={{ p: { xs: 1.5, sm: 2 } }}>
            <Button 
              fullWidth 
              variant="contained" 
              onClick={() => nav('/login')}
              size={isMobile ? 'small' : 'medium'}
              sx={{
                fontSize: { xs: '0.875rem', sm: '0.9375rem' }
              }}
            >
              Login
            </Button>
          </Box>
        )}
      </Drawer>

      <Container sx={{ py: 2, flex: 1, px: { xs: 1, sm: 1.5, md: 2 } }}>{children}</Container>
      <GlobalSearchDialog open={searchOpen} onClose={() => setSearchOpen(false)} />
    </Box>
  )
}


