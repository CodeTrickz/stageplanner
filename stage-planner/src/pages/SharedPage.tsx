import { Alert, Box, Paper, Stack, Typography } from '@mui/material'
import { useEffect, useState } from 'react'
import { apiFetch, useApiToken } from '../api/client'

type SharedPlanning = {
  id: string
  userId: string
  date: string
  start: string
  end: string
  title: string
  notes: string | null
  priority: string
  status: string
  createdAt: number
  updatedAt: number
  permission: 'read' | 'write'
  ownerId: string
}

type SharedNote = {
  id: string
  userId: string
  subject: string
  body: string
  createdAt: number
  updatedAt: number
}

export function SharedPage() {
  const token = useApiToken()
  const [planning, setPlanning] = useState<SharedPlanning[]>([])
  const [notes, setNotes] = useState<SharedNote[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    async function run() {
      if (!token) return
      setError(null)
      try {
        const p = await apiFetch('/planning?scope=shared', { token })
        const n = await apiFetch('/notes?scope=shared', { token })
        if (!cancelled) {
          setPlanning((p.shared ?? []) as SharedPlanning[])
          setNotes((n.shared ?? []) as SharedNote[])
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : 'load_failed')
      }
    }
    void run()
    return () => {
      cancelled = true
    }
  }, [token])

  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      <Typography variant="h5" sx={{ fontWeight: 800 }}>
        Gedeeld met mij
      </Typography>
      {error && <Alert severity="error">{error}</Alert>}

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography sx={{ fontWeight: 900, mb: 1 }}>Taken</Typography>
        {planning.length === 0 ? (
          <Alert severity="info">Nog geen gedeelde taken.</Alert>
        ) : (
          <Stack spacing={1}>
            {planning.map((it) => (
              <Paper key={it.id} variant="outlined" sx={{ p: 1.5 }}>
                <Typography sx={{ fontWeight: 900 }}>
                  {it.date} {it.start}-{it.end} • {it.title} ({it.permission})
                </Typography>
                {it.notes && <Typography variant="body2" color="text.secondary">{it.notes}</Typography>}
              </Paper>
            ))}
          </Stack>
        )}
      </Paper>

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography sx={{ fontWeight: 900, mb: 1 }}>Notities</Typography>
        {notes.length === 0 ? (
          <Alert severity="info">Nog geen gedeelde notities.</Alert>
        ) : (
          <Stack spacing={1}>
            {notes.map((n) => (
              <Paper key={n.id} variant="outlined" sx={{ p: 1.5 }}>
                <Typography sx={{ fontWeight: 900 }}>{n.subject || '(zonder onderwerp)'}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {new Date(n.updatedAt).toLocaleString()}
                </Typography>
              </Paper>
            ))}
          </Stack>
        )}
      </Paper>
    </Box>
  )
}








