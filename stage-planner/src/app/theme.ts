import { createTheme } from '@mui/material/styles'
import type { PaletteMode } from '@mui/material'

export function makeAppTheme(mode: PaletteMode, opts?: { compactMode?: boolean; reduceMotion?: boolean }) {
  return createTheme({
    palette: {
      mode,
      primary: { main: '#2563eb' },
      secondary: { main: '#7c3aed' },
      background: mode === 'dark' ? { default: '#0b1220' } : { default: '#f7f8fb' },
    },
    shape: { borderRadius: opts?.compactMode ? 10 : 12 },
    typography: {
      fontSize: opts?.compactMode ? 13 : 14,
      fontFamily: [
        'Inter',
        'system-ui',
        '-apple-system',
        'Segoe UI',
        'Roboto',
        'Helvetica',
        'Arial',
        'sans-serif',
      ].join(','),
    },
    transitions: opts?.reduceMotion
      ? {
          duration: {
            shortest: 0,
            shorter: 0,
            short: 0,
            standard: 0,
            complex: 0,
            enteringScreen: 0,
            leavingScreen: 0,
          },
        }
      : undefined,
  })
}


