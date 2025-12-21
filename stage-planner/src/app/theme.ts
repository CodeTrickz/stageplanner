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
    shape: { borderRadius: opts?.compactMode ? 8 : 10 },
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
      h1: {
        fontSize: '1.75rem',
        fontWeight: 800,
        '@media (min-width:600px)': {
          fontSize: '2rem',
        },
      },
      h2: {
        fontSize: '1.5rem',
        fontWeight: 800,
        '@media (min-width:600px)': {
          fontSize: '1.75rem',
        },
      },
      h3: {
        fontSize: '1.25rem',
        fontWeight: 800,
        '@media (min-width:600px)': {
          fontSize: '1.5rem',
        },
      },
      h4: {
        fontSize: '1.125rem',
        fontWeight: 800,
        '@media (min-width:600px)': {
          fontSize: '1.25rem',
        },
      },
      h5: {
        fontSize: '1rem',
        fontWeight: 800,
        '@media (min-width:600px)': {
          fontSize: '1.125rem',
        },
      },
      h6: {
        fontSize: '0.875rem',
        fontWeight: 800,
        '@media (min-width:600px)': {
          fontSize: '1rem',
        },
      },
    },
    components: {
      MuiContainer: {
        styleOverrides: {
          root: {
            paddingLeft: '1rem',
            paddingRight: '1rem',
            '@media (min-width:600px)': {
              paddingLeft: '1.5rem',
              paddingRight: '1.5rem',
            },
            '@media (min-width:960px)': {
              paddingLeft: '2rem',
              paddingRight: '2rem',
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            padding: '6px 12px',
            fontSize: '0.875rem',
            '@media (min-width:600px)': {
              padding: '8px 16px',
              fontSize: '0.9375rem',
            },
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            padding: '1rem',
            '@media (min-width:600px)': {
              padding: '1.5rem',
            },
          },
        },
      },
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


