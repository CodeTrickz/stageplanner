export type WorkspaceRole = 'STUDENT' | 'MENTOR' | 'BEGELEIDER'

export type Workspace = {
  id: string
  name: string
  description?: string | null
  joinCode?: string | null
  ownerId?: string | null
  createdAt: number
  role?: WorkspaceRole // User's role in this workspace
}

export type WorkspaceMember = {
  userId: string
  username?: string | null
  email: string
  firstName?: string | null
  lastName?: string | null
  role: WorkspaceRole
  status: 'active' | 'pending' | 'rejected' | 'revoked'
  invitedBy?: string | null
  invitedAt?: number | null
  createdAt: number
}

export type WorkspaceInvitation = {
  id: string
  workspaceId: string
  email: string
  role: WorkspaceRole
  invitedBy: string
  expiresAt: number
  acceptedAt?: number | null
  createdAt: number
}


