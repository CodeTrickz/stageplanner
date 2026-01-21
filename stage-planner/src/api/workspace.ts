import { useMemo } from 'react'
import { apiFetch, useApiToken } from './client'
import type { Workspace, WorkspaceMember, WorkspaceInvitation, WorkspaceRole } from '../types/workspace'

export async function listWorkspaces(token: string): Promise<Workspace[]> {
  const result = await apiFetch('/workspaces', { token })
  // Backend returns array directly, but handle both formats for compatibility
  return Array.isArray(result) ? result : (result.workspaces || [])
}

export async function getWorkspace(token: string, workspaceId: string): Promise<Workspace> {
  return apiFetch(`/workspaces/${workspaceId}`, { token })
}

export async function createWorkspace(
  token: string,
  data: { name: string; description?: string }
): Promise<Workspace> {
  return apiFetch('/workspaces', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(data),
    token,
  })
}

export async function updateWorkspace(
  token: string,
  workspaceId: string,
  data: { name?: string; description?: string }
): Promise<Workspace> {
  return apiFetch(`/workspaces/${workspaceId}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(data),
    token,
  })
}

export async function inviteToWorkspace(
  token: string,
  workspaceId: string,
  data: { email: string; role?: WorkspaceRole }
): Promise<{ invitation: WorkspaceInvitation }> {
  return apiFetch(`/workspaces/${workspaceId}/invite`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(data),
    token,
  })
}

export async function acceptInvitation(token: string, invitationToken: string): Promise<{ workspace: Workspace }> {
  return apiFetch('/workspaces/accept', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: invitationToken }),
    token,
  })
}

export async function listWorkspaceMembers(token: string, workspaceId: string): Promise<WorkspaceMember[]> {
  const result = await apiFetch(`/workspaces/${workspaceId}/members`, { token })
  // Backend returns array directly, but handle both formats for compatibility
  return Array.isArray(result) ? result : (result.members || [])
}

export async function listWorkspaceInvitations(token: string, workspaceId: string): Promise<WorkspaceInvitation[]> {
  return apiFetch(`/workspaces/${workspaceId}/invitations`, { token })
}

export async function updateMemberRole(
  token: string,
  workspaceId: string,
  userId: string,
  role: WorkspaceRole
): Promise<void> {
  return apiFetch(`/workspaces/${workspaceId}/members`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ userId, role }),
    token,
  })
}

export async function removeMember(token: string, workspaceId: string, userId: string): Promise<void> {
  return apiFetch(`/workspaces/${workspaceId}/members/${userId}`, {
    method: 'DELETE',
    token,
  })
}

// React hooks
export function useWorkspaces() {
  const token = useApiToken()
  return useMemo(() => ({
    listWorkspaces: () => (token ? listWorkspaces(token) : Promise.resolve([])),
    getWorkspace: (id: string) => (token ? getWorkspace(token, id) : Promise.reject(new Error('no_token'))),
    createWorkspace: (data: { name: string; description?: string }) =>
      token ? createWorkspace(token, data) : Promise.reject(new Error('no_token')),
    updateWorkspace: (id: string, data: { name?: string; description?: string }) =>
      token ? updateWorkspace(token, id, data) : Promise.reject(new Error('no_token')),
    inviteToWorkspace: (id: string, data: { email: string; role?: WorkspaceRole }) =>
      token ? inviteToWorkspace(token, id, data) : Promise.reject(new Error('no_token')),
    acceptInvitation: (invitationToken: string) =>
      token ? acceptInvitation(token, invitationToken) : Promise.reject(new Error('no_token')),
    listMembers: (id: string) => (token ? listWorkspaceMembers(token, id) : Promise.resolve([])),
    listInvitations: (id: string) => (token ? listWorkspaceInvitations(token, id) : Promise.resolve([])),
    updateMemberRole: (workspaceId: string, userId: string, role: WorkspaceRole) =>
      token ? updateMemberRole(token, workspaceId, userId, role) : Promise.reject(new Error('no_token')),
    removeMember: (workspaceId: string, userId: string) =>
      token ? removeMember(token, workspaceId, userId) : Promise.reject(new Error('no_token')),
  }), [token])
}

