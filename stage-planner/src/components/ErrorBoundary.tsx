import React from 'react'
import { Alert, Box, Button, Paper, Typography } from '@mui/material'
import { logError } from '../app/errorLog'

export class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; message: string }
> {
  state = { hasError: false, message: '' }

  static getDerivedStateFromError(err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return { hasError: true, message: msg }
  }

  componentDidCatch(error: unknown, info: any) {
    void logError('react', error, { componentStack: info?.componentStack })
  }

  render() {
    if (!this.state.hasError) return this.props.children
    return (
      <Box sx={{ py: 3 }}>
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 900 }}>
            Er ging iets mis
          </Typography>
          <Alert severity="error" sx={{ mt: 1 }}>
            {this.state.message || 'Onbekende fout'}
          </Alert>
          <Button sx={{ mt: 2 }} variant="contained" onClick={() => window.location.reload()}>
            Herlaad pagina
          </Button>
        </Paper>
      </Box>
    )
  }
}









