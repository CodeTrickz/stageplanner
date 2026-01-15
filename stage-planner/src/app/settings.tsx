import React, { createContext, useContext, useEffect, useMemo, useState } from 'react'
import type { PaletteMode } from '@mui/material'

export type WeekStart = 'monday' | 'sunday'
export type TimeFormat = '24h' | '12h'
export type StartPage = '/dashboard' | '/planning' | '/week' | '/taken' | '/bestanden' | '/notities'
export type WeekViewMode = 'full' | 'workweek'
export type PlanningPriority = 'low' | 'medium' | 'high'
export type PlanningStatus = 'todo' | 'in_progress' | 'done'

type SettingsState = {
  mode: PaletteMode
  weekStart: WeekStart
  timeFormat: TimeFormat
  startPage: StartPage
  weekViewMode: WeekViewMode
  defaultTaskMinutes: number
  defaultPriority: PlanningPriority
  defaultStatus: PlanningStatus
  workdayStart: string // HH:mm
  workdayEnd: string // HH:mm
  compactMode: boolean
  reduceMotion: boolean

  // Stage planning
  stageStart: string // YYYY-MM-DD
  stageEnd: string // YYYY-MM-DD
  stageHolidaysJson: string // string[]

  // Files / preview
  autoExtractTextOnOpen: boolean
  ocrLanguage: string

  // Privacy / diagnostics
  errorLoggingEnabled: boolean
  errorLogRetentionDays: number // 0 = keep forever
  errorLogMaxEntries: number

  // Security / session
  idleLogoutMinutes: number // 0 = never
}

type Settings = SettingsState & {
  setMode: (m: PaletteMode) => void
  toggleMode: () => void
  setWeekStart: (v: WeekStart) => void
  setTimeFormat: (v: TimeFormat) => void
  setStartPage: (v: StartPage) => void
  setWeekViewMode: (v: WeekViewMode) => void
  setDefaultTaskMinutes: (v: number) => void
  setDefaultPriority: (v: PlanningPriority) => void
  setDefaultStatus: (v: PlanningStatus) => void
  setWorkdayStart: (v: string) => void
  setWorkdayEnd: (v: string) => void
  setCompactMode: (v: boolean) => void
  setReduceMotion: (v: boolean) => void

  setStageStart: (v: string) => void
  setStageEnd: (v: string) => void
  setStageHolidaysJson: (v: string) => void

  setAutoExtractTextOnOpen: (v: boolean) => void
  setOcrLanguage: (v: string) => void

  setErrorLoggingEnabled: (v: boolean) => void
  setErrorLogRetentionDays: (v: number) => void
  setErrorLogMaxEntries: (v: number) => void

  setIdleLogoutMinutes: (v: number) => void
}

const SettingsContext = createContext<Settings | null>(null)
const KEY = 'stageplanner.settings.v1'

function isTimeHm(v: unknown): v is string {
  return typeof v === 'string' && /^\d{2}:\d{2}$/.test(v)
}

function clampInt(n: number, min: number, max: number) {
  if (!Number.isFinite(n)) return min
  return Math.min(max, Math.max(min, Math.round(n)))
}

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<PaletteMode>('light')
  const [weekStart, setWeekStart] = useState<WeekStart>('monday')
  const [timeFormat, setTimeFormat] = useState<TimeFormat>('24h')
  const [startPage, setStartPage] = useState<StartPage>('/dashboard')
  const [weekViewMode, setWeekViewMode] = useState<WeekViewMode>('full')
  const [defaultTaskMinutes, setDefaultTaskMinutes] = useState<number>(60)
  const [workdayStart, setWorkdayStart] = useState('09:00')
  const [workdayEnd, setWorkdayEnd] = useState('17:00')
  const [defaultPriority, setDefaultPriority] = useState<PlanningPriority>('medium')
  const [defaultStatus, setDefaultStatus] = useState<PlanningStatus>('todo')
  const [compactMode, setCompactMode] = useState(false)
  const [reduceMotion, setReduceMotion] = useState(false)
  const [stageStart, setStageStart] = useState('2026-02-02')
  const [stageEnd, setStageEnd] = useState('2026-05-31')
  const [stageHolidaysJson, setStageHolidaysJson] = useState('[]')
  const [autoExtractTextOnOpen, setAutoExtractTextOnOpen] = useState(false)
  const [ocrLanguage, setOcrLanguage] = useState('eng')
  const [errorLoggingEnabled, setErrorLoggingEnabled] = useState(true)
  const [errorLogRetentionDays, setErrorLogRetentionDays] = useState(14)
  const [errorLogMaxEntries, setErrorLogMaxEntries] = useState(500)
  const [idleLogoutMinutes, setIdleLogoutMinutes] = useState(30)

  useEffect(() => {
    try {
      const raw = localStorage.getItem(KEY)
      if (!raw) return
      const parsed = JSON.parse(raw) as Partial<SettingsState>
      if (parsed?.mode === 'dark' || parsed?.mode === 'light') setMode(parsed.mode)
      if (parsed?.weekStart === 'monday' || parsed?.weekStart === 'sunday') setWeekStart(parsed.weekStart)
      if (parsed?.timeFormat === '24h' || parsed?.timeFormat === '12h') setTimeFormat(parsed.timeFormat)
      if (
        parsed?.startPage === '/dashboard' ||
        parsed?.startPage === '/planning' ||
        parsed?.startPage === '/week' ||
        parsed?.startPage === '/taken' ||
        parsed?.startPage === '/bestanden' ||
        parsed?.startPage === '/notities'
      )
        setStartPage(parsed.startPage)
      if (parsed?.weekViewMode === 'full' || parsed?.weekViewMode === 'workweek') setWeekViewMode(parsed.weekViewMode)

      if (typeof parsed?.defaultTaskMinutes === 'number') setDefaultTaskMinutes(clampInt(parsed.defaultTaskMinutes, 5, 8 * 60))
      if (parsed?.defaultPriority === 'low' || parsed?.defaultPriority === 'medium' || parsed?.defaultPriority === 'high')
        setDefaultPriority(parsed.defaultPriority)
      if (parsed?.defaultStatus === 'todo' || parsed?.defaultStatus === 'in_progress' || parsed?.defaultStatus === 'done')
        setDefaultStatus(parsed.defaultStatus)

      if (isTimeHm(parsed?.workdayStart)) setWorkdayStart(parsed.workdayStart)
      if (isTimeHm(parsed?.workdayEnd)) setWorkdayEnd(parsed.workdayEnd)

      if (typeof parsed?.compactMode === 'boolean') setCompactMode(parsed.compactMode)
      if (typeof parsed?.reduceMotion === 'boolean') setReduceMotion(parsed.reduceMotion)

      if (typeof parsed?.stageStart === 'string') setStageStart(parsed.stageStart)
      if (typeof parsed?.stageEnd === 'string') setStageEnd(parsed.stageEnd)
      if (typeof parsed?.stageHolidaysJson === 'string') setStageHolidaysJson(parsed.stageHolidaysJson)

      if (typeof parsed?.autoExtractTextOnOpen === 'boolean') setAutoExtractTextOnOpen(parsed.autoExtractTextOnOpen)
      if (typeof parsed?.ocrLanguage === 'string' && parsed.ocrLanguage.trim()) setOcrLanguage(parsed.ocrLanguage.trim())

      if (typeof parsed?.errorLoggingEnabled === 'boolean') setErrorLoggingEnabled(parsed.errorLoggingEnabled)
      if (typeof parsed?.errorLogRetentionDays === 'number') setErrorLogRetentionDays(clampInt(parsed.errorLogRetentionDays, 0, 365))
      if (typeof parsed?.errorLogMaxEntries === 'number') setErrorLogMaxEntries(clampInt(parsed.errorLogMaxEntries, 50, 5000))

      if (typeof parsed?.idleLogoutMinutes === 'number') setIdleLogoutMinutes(clampInt(parsed.idleLogoutMinutes, 0, 240))
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
        startPage,
        weekViewMode,
        defaultTaskMinutes,
        defaultPriority,
        defaultStatus,
        workdayStart,
        workdayEnd,
        compactMode,
        reduceMotion,
        stageStart,
        stageEnd,
        stageHolidaysJson,
        autoExtractTextOnOpen,
        ocrLanguage,
        errorLoggingEnabled,
        errorLogRetentionDays,
        errorLogMaxEntries,
        idleLogoutMinutes,
      }
      localStorage.setItem(KEY, JSON.stringify(next))
    } catch {
      // ignore
    }
  }, [
    mode,
    weekStart,
    timeFormat,
    startPage,
    weekViewMode,
    defaultTaskMinutes,
    defaultPriority,
    defaultStatus,
    workdayStart,
    workdayEnd,
    compactMode,
    reduceMotion,
    stageStart,
    stageEnd,
    stageHolidaysJson,
    autoExtractTextOnOpen,
    ocrLanguage,
    errorLoggingEnabled,
    errorLogRetentionDays,
    errorLogMaxEntries,
    idleLogoutMinutes,
  ])

  const value = useMemo<Settings>(
    () => ({
      mode,
      setMode,
      toggleMode: () => setMode((m) => (m === 'dark' ? 'light' : 'dark')),
      weekStart,
      setWeekStart,
      timeFormat,
      setTimeFormat,
      startPage,
      setStartPage,
      weekViewMode,
      setWeekViewMode,
      defaultTaskMinutes,
      setDefaultTaskMinutes,
      workdayStart,
      setWorkdayStart,
      workdayEnd,
      setWorkdayEnd,
      defaultPriority,
      setDefaultPriority,
      defaultStatus,
      setDefaultStatus,
      compactMode,
      setCompactMode,
      reduceMotion,
      setReduceMotion,

      stageStart,
      setStageStart,
      stageEnd,
      setStageEnd,
      stageHolidaysJson,
      setStageHolidaysJson,

      autoExtractTextOnOpen,
      setAutoExtractTextOnOpen,
      ocrLanguage,
      setOcrLanguage,

      errorLoggingEnabled,
      setErrorLoggingEnabled,
      errorLogRetentionDays,
      setErrorLogRetentionDays,
      errorLogMaxEntries,
      setErrorLogMaxEntries,

      idleLogoutMinutes,
      setIdleLogoutMinutes,
    }),
    [
      mode,
      weekStart,
      timeFormat,
      startPage,
      weekViewMode,
      defaultTaskMinutes,
      defaultPriority,
      defaultStatus,
      workdayStart,
      workdayEnd,
      compactMode,
      reduceMotion,
      stageStart,
      stageEnd,
      stageHolidaysJson,
      autoExtractTextOnOpen,
      ocrLanguage,
      errorLoggingEnabled,
      errorLogRetentionDays,
      errorLogMaxEntries,
      idleLogoutMinutes,
    ],
  )

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
}

export function useSettings() {
  const ctx = useContext(SettingsContext)
  if (!ctx) throw new Error('useSettings must be used within SettingsProvider')
  return ctx
}



