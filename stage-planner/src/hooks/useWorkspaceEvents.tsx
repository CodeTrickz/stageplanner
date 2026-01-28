import { useEffect, useRef } from 'react'
import { API_BASE } from '../api/client'
import { useApiToken } from '../api/client'
import { useWorkspace } from './useWorkspace'

export type WorkspaceEvent = {
  type: string
  workspaceId: string
  ts: number
}

export function useWorkspaceEvents(onEvent: (evt: WorkspaceEvent) => void) {
  const token = useApiToken()
  const { currentWorkspace } = useWorkspace()
  const onEventRef = useRef(onEvent)

  // Keep latest handler without forcing a reconnect
  useEffect(() => {
    onEventRef.current = onEvent
  }, [onEvent])

  useEffect(() => {
    if (!token || !currentWorkspace?.id) return
    const wsId = String(currentWorkspace.id)
    const url = `${API_BASE}/events?workspaceId=${encodeURIComponent(wsId)}&token=${encodeURIComponent(token)}`
    const es = new EventSource(url)
    const handler = (e: MessageEvent<string>) => {
      try {
        const data = JSON.parse(e.data) as WorkspaceEvent
        if (data.workspaceId === wsId) onEventRef.current(data)
      } catch {
        // ignore
      }
    }
    es.addEventListener('update', handler as EventListener)
    es.addEventListener('ready', handler as EventListener)
    return () => {
      es.removeEventListener('update', handler as EventListener)
      es.removeEventListener('ready', handler as EventListener)
      es.close()
    }
  }, [token, currentWorkspace?.id])
}
