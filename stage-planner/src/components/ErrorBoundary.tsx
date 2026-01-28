import React from 'react'
import { Alert, Box, Button, Paper, Typography } from '@mui/material'
import { logError } from '../app/errorLog'
import { getLastTraceId } from '../api/client'

export class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; message: string }
> {
  state = { hasError: false, message: '' }

  static getDerivedStateFromError(err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return { hasError: true, message: msg }
  }

  componentDidCatch(error: unknown, info: React.ErrorInfo) {
    void logError('react', error, { componentStack: info?.componentStack })
  }

  render() {
    if (!this.state.hasError) return this.props.children
    const traceId = getLastTraceId()
    return (
      <Box sx={{ py: 3 }}>
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 900 }}>
            Er ging iets mis
          </Typography>
          <Alert severity="error" sx={{ mt: 1 }}>
            {this.state.message || 'Onbekende fout'}
          </Alert>
          {traceId && (
            <Alert severity="info" sx={{ mt: 1 }}>
              TraceId: <b>{traceId}</b>
            </Alert>
          )}
          <Button sx={{ mt: 2 }} variant="contained" onClick={() => window.location.reload()}>
            Herlaad pagina
          </Button>
          {traceId && (
            <Button
              sx={{ mt: 2, ml: 1 }}
              variant="outlined"
              onClick={() => {
                void navigator.clipboard?.writeText(traceId)
              }}
            >
              Kopieer traceId
            </Button>
          )}
        </Paper>
      </Box>
    )
  }
}









