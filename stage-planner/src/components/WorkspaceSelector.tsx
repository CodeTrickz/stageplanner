import { useState } from 'react'
import {
  Box,
  Button,
  Chip,
  ListItemText,
  Menu,
  MenuItem,
  Typography,
} from '@mui/material'
import WorkspacesIcon from '@mui/icons-material/Workspaces'
import { useWorkspace } from '../hooks/useWorkspace'
import type { Workspace } from '../types/workspace'

const roleLabels: Record<string, string> = {
  STUDENT: 'Student',
  MENTOR: 'Mentor',
  BEGELEIDER: 'Begeleider',
}

export function WorkspaceSelector() {
  const { currentWorkspace, workspaces, setCurrentWorkspace, loading, error } = useWorkspace()
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null)
  const open = Boolean(anchorEl)

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget)
  }

  const handleClose = () => {
    setAnchorEl(null)
  }

  const handleSelect = (workspace: Workspace) => {
    setCurrentWorkspace(workspace)
    handleClose()
  }

  if (loading) {
    return (
      <Box sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Typography variant="body2" color="text.secondary">
          Workspaces laden...
        </Typography>
      </Box>
    )
  }

  if (error) {
    return (
      <Box sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Typography variant="body2" color="error">
          Fout: {error}
        </Typography>
      </Box>
    )
  }

  if (workspaces.length === 0) {
    return (
      <Box sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Typography variant="body2" color="text.secondary">
          Geen workspaces beschikbaar
        </Typography>
      </Box>
    )
  }

  return (
    <>
      <Box sx={{ mb: 1 }}>
        <Typography 
          variant="caption" 
          color="text.secondary" 
          sx={{ 
            fontSize: { xs: '0.7rem', sm: '0.75rem' },
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: 0.5,
            px: { xs: 1.5, sm: 2 },
            pb: 0.5,
            display: 'block'
          }}
        >
          Workspace
        </Typography>
      </Box>
      <Button
        onClick={handleClick}
        startIcon={<WorkspacesIcon />}
        sx={{
          textTransform: 'none',
          color: 'text.primary',
          justifyContent: 'flex-start',
          px: { xs: 1.5, sm: 2 },
          py: { xs: 1, sm: 1.25 },
          border: '1px solid',
          borderColor: 'divider',
          borderRadius: 1,
          '&:hover': {
            borderColor: 'primary.main',
            bgcolor: 'action.hover',
          },
        }}
        fullWidth
      >
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', flex: 1, minWidth: 0 }}>
          <Typography
            variant="body2"
            sx={{
              fontSize: { xs: '0.75rem', sm: '0.8125rem' },
              fontWeight: 600,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              width: '100%',
            }}
          >
            {currentWorkspace?.name || 'Geen workspace'}
          </Typography>
          {currentWorkspace?.role && (
            <Chip
              label={roleLabels[currentWorkspace.role] || currentWorkspace.role}
              size="small"
              sx={{ mt: 0.5, height: 20, fontSize: '0.7rem' }}
            />
          )}
          {workspaces.length > 1 && (
            <Typography 
              variant="caption" 
              color="text.secondary" 
              sx={{ 
                mt: 0.5,
                fontSize: '0.65rem',
                fontStyle: 'italic'
              }}
            >
              Klik om te wisselen ({workspaces.length} beschikbaar)
            </Typography>
          )}
        </Box>
      </Button>
      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        PaperProps={{
          sx: {
            maxHeight: 400,
            width: { xs: '85vw', sm: 300, md: 320 },
            maxWidth: { xs: '85vw', sm: '90vw' },
          },
        }}
      >
        <Box sx={{ px: 2, py: 1, borderBottom: 1, borderColor: 'divider' }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 600, fontSize: '0.75rem' }}>
            Selecteer Workspace
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
            {workspaces.length} workspace{workspaces.length !== 1 ? 's' : ''} beschikbaar
          </Typography>
        </Box>
        {workspaces.map((ws) => (
          <MenuItem
            key={ws.id}
            selected={currentWorkspace?.id === ws.id}
            onClick={() => handleSelect(ws)}
            sx={{ 
              py: 1.5, 
              px: 2,
              bgcolor: currentWorkspace?.id === ws.id ? 'action.selected' : 'transparent',
            }}
          >
            <ListItemText
              primary={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography variant="body2" sx={{ fontWeight: currentWorkspace?.id === ws.id ? 600 : 400 }}>
                    {ws.name}
                  </Typography>
                  {currentWorkspace?.id === ws.id && (
                    <Chip
                      label="Actief"
                      size="small"
                      color="primary"
                      sx={{ height: 18, fontSize: '0.65rem' }}
                    />
                  )}
                </Box>
              }
              secondary={
                <Box sx={{ display: 'flex', gap: 1, mt: 0.5, alignItems: 'center' }}>
                  {ws.role && (
                    <Chip
                      label={roleLabels[ws.role] || ws.role}
                      size="small"
                      color={ws.role === 'STUDENT' ? 'primary' : ws.role === 'MENTOR' ? 'secondary' : 'default'}
                      sx={{ height: 20, fontSize: '0.7rem' }}
                    />
                  )}
                  {ws.description && (
                    <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
                      {ws.description}
                    </Typography>
                  )}
                </Box>
              }
            />
          </MenuItem>
        ))}
      </Menu>
    </>
  )
}

