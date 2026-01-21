import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Box,
  Button,
  Card,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  IconButton,
  List,
  ListItem,
  ListItemText,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import DeleteIcon from '@mui/icons-material/Delete'
import PersonAddIcon from '@mui/icons-material/PersonAdd'
import { useWorkspace } from '../hooks/useWorkspace'
import { useWorkspaces } from '../api/workspace'
import { useAuth } from '../auth/auth'
import type { WorkspaceMember, WorkspaceRole, WorkspaceInvitation } from '../types/workspace'
import { getWorkspacePermissions } from '../utils/permissions'

const roleLabels: Record<WorkspaceRole, string> = {
  OWNER: 'Owner',
  EDITOR: 'Editor',
  COMMENTER: 'Commenter',
  VIEWER: 'Viewer',
}

const statusLabels: Record<string, string> = {
  active: 'Actief',
  pending: 'In afwachting',
  rejected: 'Geweigerd',
  revoked: 'Ingetrokken',
}

export function TeamPage() {
  const { currentWorkspace } = useWorkspace()
  const { user } = useAuth()
  const api = useWorkspaces()
  const [members, setMembers] = useState<WorkspaceMember[]>([])
  const [invitations, setInvitations] = useState<WorkspaceInvitation[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [inviteDialogOpen, setInviteDialogOpen] = useState(false)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState<WorkspaceRole>('VIEWER')
  const [inviting, setInviting] = useState(false)

  const permissions = getWorkspacePermissions(currentWorkspace?.role)
  const canManageTeam = permissions.isOwner

  const loadMembers = useCallback(async () => {
    if (!currentWorkspace) {
      setLoading(false)
      return
    }
    try {
      setError(null)
      setLoading(true)
      const [membersList, invitationsList] = await Promise.all([
        api.listMembers(currentWorkspace.id),
        canManageTeam ? api.listInvitations(currentWorkspace.id) : Promise.resolve([]),
      ])
      setMembers(membersList)
      setInvitations(invitationsList)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed_to_load_members')
    } finally {
      setLoading(false)
    }
  }, [currentWorkspace?.id, api, canManageTeam])

  useEffect(() => {
    void loadMembers()
  }, [loadMembers])

  async function handleInvite() {
    if (!currentWorkspace || !inviteEmail.trim()) return
    try {
      setInviting(true)
      setError(null)
      await api.inviteToWorkspace(currentWorkspace.id, {
        email: inviteEmail.trim(),
        role: inviteRole,
      })
      setInviteDialogOpen(false)
      setInviteEmail('')
      await loadMembers()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed_to_invite')
    } finally {
      setInviting(false)
    }
  }

  async function handleUpdateRole(memberUserId: string, newRole: WorkspaceRole) {
    if (!currentWorkspace) return
    try {
      setError(null)
      await api.updateMemberRole(currentWorkspace.id, memberUserId, newRole)
      await loadMembers()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed_to_update_role')
    }
  }

  async function handleRemoveMember(memberUserId: string) {
    if (!currentWorkspace) return
    if (!confirm('Weet je zeker dat je dit lid wilt verwijderen?')) return
    try {
      setError(null)
      await api.removeMember(currentWorkspace.id, memberUserId)
      await loadMembers()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed_to_remove_member')
    }
  }

  if (!currentWorkspace) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="info">Selecteer eerst een workspace</Alert>
      </Box>
    )
  }

  return (
    <Box sx={{ p: { xs: 2, sm: 3 } }}>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 3 }}>
        <Typography variant="h4" component="h1">
          Team: {currentWorkspace.name}
        </Typography>
        {canManageTeam && (
          <Button
            variant="contained"
            startIcon={<PersonAddIcon />}
            onClick={() => setInviteDialogOpen(true)}
          >
            Uitnodigen
          </Button>
        )}
      </Stack>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {loading ? (
        <Alert severity="info">Laden…</Alert>
      ) : members.length === 0 && invitations.length === 0 ? (
        <Alert severity="info">Nog geen teamleden</Alert>
      ) : (
        <>
          {invitations.length > 0 && (
            <Card sx={{ mb: 2 }}>
              <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
                <Typography variant="h6">Uitnodigingen in afwachting</Typography>
              </Box>
              <List>
                {invitations
                  .filter((inv) => !inv.acceptedAt)
                  .map((inv) => (
                    <ListItem key={inv.id}>
                      <ListItemText
                        primary={inv.email}
                        secondary={
                          <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                            <Chip
                              label={roleLabels[inv.role as WorkspaceRole]}
                              size="small"
                              color={inv.role === 'OWNER' ? 'primary' : inv.role === 'EDITOR' ? 'secondary' : 'default'}
                            />
                            <Typography variant="caption" color="text.secondary">
                              Verloopt: {new Date(inv.expiresAt).toLocaleDateString('nl-NL')}
                            </Typography>
                          </Stack>
                        }
                      />
                    </ListItem>
                  ))}
              </List>
            </Card>
          )}
          <Card>
            <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
              <Typography variant="h6">Teamleden</Typography>
            </Box>
            <List>
              {members.map((member) => (
              <ListItem
                key={member.userId}
                secondaryAction={
                  canManageTeam && member.userId !== user?.id ? (
                    <Stack direction="row" spacing={1}>
                      <Select
                        value={member.role}
                        onChange={(e) => handleUpdateRole(member.userId, e.target.value as WorkspaceRole)}
                        size="small"
                        sx={{ minWidth: 120 }}
                      >
                        <MenuItem value="OWNER">{roleLabels.OWNER}</MenuItem>
                        <MenuItem value="EDITOR">{roleLabels.EDITOR}</MenuItem>
                        <MenuItem value="COMMENTER">{roleLabels.COMMENTER}</MenuItem>
                        <MenuItem value="VIEWER">{roleLabels.VIEWER}</MenuItem>
                      </Select>
                      <IconButton
                        edge="end"
                        color="error"
                        onClick={() => handleRemoveMember(member.userId)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Stack>
                  ) : (
                    <Chip
                      label={roleLabels[member.role]}
                      size="small"
                      color={member.role === 'OWNER' ? 'primary' : member.role === 'EDITOR' ? 'secondary' : 'default'}
                    />
                  )
                }
              >
                <ListItemText
                  primary={
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography variant="body1">
                        {member.firstName && member.lastName
                          ? `${member.firstName} ${member.lastName}`
                          : member.username || member.email}
                      </Typography>
                      {member.status !== 'active' && (
                        <Chip
                          label={statusLabels[member.status] || member.status}
                          size="small"
                          color="warning"
                          variant="outlined"
                        />
                      )}
                    </Stack>
                  }
                  secondary={
                    <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                      <Typography variant="caption" color="text.secondary">
                        {member.email}
                      </Typography>
                      {member.userId === user?.id && (
                        <Chip label="Jij" size="small" variant="outlined" />
                      )}
                    </Stack>
                  }
                />
              </ListItem>
            ))}
          </List>
        </Card>
        </>
      )}

      <Dialog open={inviteDialogOpen} onClose={() => setInviteDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Lid uitnodigen</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="E-mailadres"
              type="email"
              fullWidth
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              autoFocus
            />
            <FormControl fullWidth>
              <Typography variant="body2" sx={{ mb: 1 }}>
                Rol
              </Typography>
              <Select value={inviteRole} onChange={(e) => setInviteRole(e.target.value as WorkspaceRole)}>
                <MenuItem value="OWNER">{roleLabels.OWNER}</MenuItem>
                <MenuItem value="EDITOR">{roleLabels.EDITOR}</MenuItem>
                <MenuItem value="COMMENTER">{roleLabels.COMMENTER}</MenuItem>
                <MenuItem value="VIEWER">{roleLabels.VIEWER}</MenuItem>
              </Select>
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setInviteDialogOpen(false)}>Annuleren</Button>
          <Button onClick={handleInvite} variant="contained" disabled={!inviteEmail.trim() || inviting}>
            {inviting ? 'Uitnodigen…' : 'Uitnodigen'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

