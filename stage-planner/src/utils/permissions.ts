import type { WorkspaceRole } from '../types/workspace'

export function getWorkspacePermissions(role?: WorkspaceRole) {
  if (!role) {
    return { canView: false, canComment: false, canEdit: false, isOwner: false }
  }
  switch (role) {
    case 'OWNER':
      return { canView: true, canComment: true, canEdit: true, isOwner: true }
    case 'EDITOR':
      return { canView: true, canComment: true, canEdit: true, isOwner: false }
    case 'COMMENTER':
      return { canView: true, canComment: true, canEdit: false, isOwner: false }
    case 'VIEWER':
      return { canView: true, canComment: false, canEdit: false, isOwner: false }
    default:
      return { canView: false, canComment: false, canEdit: false, isOwner: false }
  }
}

export function canView(role?: WorkspaceRole) {
  return getWorkspacePermissions(role).canView
}

export function canComment(role?: WorkspaceRole) {
  return getWorkspacePermissions(role).canComment
}

export function canEdit(role?: WorkspaceRole) {
  return getWorkspacePermissions(role).canEdit
}
