import React, { createContext, useContext, useEffect, useMemo, useState } from 'react'
import type { PaletteMode } from '@mui/material'

export type WeekStart = 'monday' | 'sunday'
export type TimeFormat = '24h' | '12h'

type SettingsState = {
  mode: PaletteMode
  weekStart: WeekStart
  timeFormat: TimeFormat
  defaultTaskMinutes: number
  workdayStart: string // HH:mm
  workdayEnd: string // HH:mm
  compactMode: boolean
  reduceMotion: boolean
}

type Settings = SettingsState & {
  setMode: (m: PaletteMode) => void
  toggleMode: () => void
  setWeekStart: (v: WeekStart) => void
  setTimeFormat: (v: TimeFormat) => void
  setDefaultTaskMinutes: (v: number) => void
  setWorkdayStart: (v: string) => void
  setWorkdayEnd: (v: string) => void
  setCompactMode: (v: boolean) => void
  setReduceMotion: (v: boolean) => void
}

const SettingsContext = createContext<Settings | null>(null)
const KEY = 'stageplanner.settings.v1'

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<PaletteMode>('light')
  const [weekStart, setWeekStart] = useState<WeekStart>('monday')
  const [timeFormat, setTimeFormat] = useState<TimeFormat>('24h')
  const [defaultTaskMinutes, setDefaultTaskMinutes] = useState<number>(60)
  const [workdayStart, setWorkdayStart] = useState('09:00')
  const [workdayEnd, setWorkdayEnd] = useState('17:00')
  const [compactMode, setCompactMode] = useState(false)
  const [reduceMotion, setReduceMotion] = useState(false)

  useEffect(() => {
    try {
      const raw = localStorage.getItem(KEY)
      if (!raw) return
      const parsed = JSON.parse(raw) as Partial<SettingsState>
      if (parsed?.mode === 'dark' || parsed?.mode === 'light') setMode(parsed.mode)
      if (parsed?.weekStart === 'monday' || parsed?.weekStart === 'sunday') setWeekStart(parsed.weekStart)
      if (parsed?.timeFormat === '24h' || parsed?.timeFormat === '12h') setTimeFormat(parsed.timeFormat)
      if (typeof parsed?.defaultTaskMinutes === 'number' && Number.isFinite(parsed.defaultTaskMinutes))
        setDefaultTaskMinutes(Math.min(8 * 60, Math.max(5, Math.round(parsed.defaultTaskMinutes))))
      if (typeof parsed?.workdayStart === 'string' && /^\d{2}:\d{2}$/.test(parsed.workdayStart)) setWorkdayStart(parsed.workdayStart)
      if (typeof parsed?.workdayEnd === 'string' && /^\d{2}:\d{2}$/.test(parsed.workdayEnd)) setWorkdayEnd(parsed.workdayEnd)
      if (typeof parsed?.compactMode === 'boolean') setCompactMode(parsed.compactMode)
      if (typeof parsed?.reduceMotion === 'boolean') setReduceMotion(parsed.reduceMotion)
    } catch {
      // ignore
    }
  }, [])

  useEffect(() => {
    try {
      const next: SettingsState = {
        mode,
        weekStart,
        timeFormat,
        defaultTaskMinutes,
        workdayStart,
        workdayEnd,
        compactMode,
        reduceMotion,
      }
      localStorage.setItem(KEY, JSON.stringify(next))
    } catch {
      // ignore
    }
  }, [mode, weekStart, timeFormat, defaultTaskMinutes, workdayStart, workdayEnd, compactMode, reduceMotion])

  const value = useMemo<Settings>(
    () => ({
      mode,
      setMode,
      toggleMode: () => setMode((m) => (m === 'dark' ? 'light' : 'dark')),
      weekStart,
      setWeekStart,
      timeFormat,
      setTimeFormat,
      defaultTaskMinutes,
      setDefaultTaskMinutes,
      workdayStart,
      setWorkdayStart,
      workdayEnd,
      setWorkdayEnd,
      compactMode,
      setCompactMode,
      reduceMotion,
      setReduceMotion,
    }),
    [mode, weekStart, timeFormat, defaultTaskMinutes, workdayStart, workdayEnd, compactMode, reduceMotion],
  )

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
}

export function useSettings() {
  const ctx = useContext(SettingsContext)
  if (!ctx) throw new Error('useSettings must be used within SettingsProvider')
  return ctx
}



