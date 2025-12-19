import React from 'react'
import ReactDOM from 'react-dom/client'
import { CssBaseline, ThemeProvider } from '@mui/material'
import { BrowserRouter } from 'react-router-dom'
import App from './App.tsx'
import { AuthProvider } from './auth/auth'
import { makeAppTheme } from './app/theme'
import { SettingsProvider, useSettings } from './app/settings'
import { ErrorBoundary } from './components/ErrorBoundary'
import { ErrorCapture } from './components/ErrorCapture'
import './index.css'

function AppThemeProvider({ children }: { children: React.ReactNode }) {
  const { mode, compactMode, reduceMotion } = useSettings()
  return <ThemeProvider theme={makeAppTheme(mode, { compactMode, reduceMotion })}>{children}</ThemeProvider>
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <SettingsProvider>
      <AppThemeProvider>
        <CssBaseline />
        <AuthProvider>
          <BrowserRouter>
            <ErrorCapture />
            <ErrorBoundary>
              <App />
            </ErrorBoundary>
          </BrowserRouter>
        </AuthProvider>
      </AppThemeProvider>
    </SettingsProvider>
  </React.StrictMode>,
)
