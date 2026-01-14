import React, { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { useWorkspaces } from '../api/workspace'
import type { Workspace } from '../types/workspace'

type WorkspaceContextType = {
  currentWorkspace: Workspace | null
  workspaces: Workspace[]
  loading: boolean
  error: string | null
  setCurrentWorkspace: (workspace: Workspace | null) => void
  refreshWorkspaces: () => Promise<void>
}

const WorkspaceContext = createContext<WorkspaceContextType | null>(null)

const WORKSPACE_STORAGE_KEY = 'stage-planner-current-workspace-id'

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const [currentWorkspace, setCurrentWorkspaceState] = useState<Workspace | null>(null)
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const api = useWorkspaces()

  const setCurrentWorkspace = useCallback((workspace: Workspace | null) => {
    setCurrentWorkspaceState(workspace)
    if (workspace) {
      localStorage.setItem(WORKSPACE_STORAGE_KEY, workspace.id)
    } else {
      localStorage.removeItem(WORKSPACE_STORAGE_KEY)
    }
  }, [])

  const refreshWorkspaces = useCallback(async () => {
    try {
      setError(null)
      const list = await api.listWorkspaces()
      setWorkspaces(list)
      
      // Restore or set current workspace
      const storedId = localStorage.getItem(WORKSPACE_STORAGE_KEY)
      if (storedId) {
        const stored = list.find((w) => w.id === storedId)
        if (stored) {
          setCurrentWorkspaceState(stored)
          return
        }
      }
      
      // Default to first workspace or personal workspace
      if (list.length > 0) {
        const personal = list.find((w) => w.role === 'STUDENT' && w.ownerId) || list[0]
        setCurrentWorkspaceState(personal)
        if (personal) {
          localStorage.setItem(WORKSPACE_STORAGE_KEY, personal.id)
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed_to_load_workspaces')
    } finally {
      setLoading(false)
    }
  }, [api])

  useEffect(() => {
    void refreshWorkspaces()
  }, [refreshWorkspaces])

  return (
    <WorkspaceContext.Provider
      value={{
        currentWorkspace,
        workspaces,
        loading,
        error,
        setCurrentWorkspace,
        refreshWorkspaces,
      }}
    >
      {children}
    </WorkspaceContext.Provider>
  )
}

export function useWorkspace() {
  const ctx = useContext(WorkspaceContext)
  if (!ctx) {
    throw new Error('useWorkspace must be used within WorkspaceProvider')
  }
  return ctx
}




