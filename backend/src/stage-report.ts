import type { DbPlanningItem } from './db'
import { db } from './db'

export type StageReportItem = {
  date: string
  week: string
  title: string
  status: DbPlanningItem['status']
  hours: number
  tags: string[]
  isStageWork: boolean
}

export type StageReportDay = {
  date: string
  items: StageReportItem[]
  totalHours: number
}

export type StageReportSummary = {
  totalDays: number
  totalItems: number
  totalHours: number
  completedItems: number
  completedHours: number
  stageWorkHours: number
  averageHoursPerDay: number
}

export type StageReportWeekSummary = {
  week: string
  totalItems: number
  totalHours: number
  statusCounts: Record<DbPlanningItem['status'], number>
}

export type StageReport = {
  workspaceName: string
  studentName?: string
  periodFrom: string
  periodTo: string
  exportDate: string
  days: StageReportDay[]
  weeks: StageReportWeekSummary[]
  summary: StageReportSummary
}

function parseTimeToMinutes(value: string): number | null {
  const match = /^(\d{1,2}):(\d{2})$/.exec(value)
  if (!match) return null
  const hours = Number(match[1])
  const mins = Number(match[2])
  if (!Number.isFinite(hours) || !Number.isFinite(mins)) return null
  return hours * 60 + mins
}

function computeHours(start: string, end: string): number {
  const startMins = parseTimeToMinutes(start)
  const endMins = parseTimeToMinutes(end)
  if (startMins == null || endMins == null) return 0
  if (endMins <= startMins) return 0
  return (endMins - startMins) / 60
}

function parseTags(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((t) => typeof t === 'string') as string[]
  if (typeof raw === 'string') {
    const trimmed = raw.trim()
    if (!trimmed) return []
    try {
      const parsed = JSON.parse(trimmed)
      if (Array.isArray(parsed)) return parsed.filter((t) => typeof t === 'string') as string[]
    } catch {
      // fall through
    }
    return trimmed
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean)
  }
  return []
}

function isoWeekKey(dateStr: string): string {
  const date = new Date(`${dateStr}T00:00:00.000Z`)
  const day = date.getUTCDay() || 7
  date.setUTCDate(date.getUTCDate() + 4 - day)
  const yearStart = new Date(Date.UTC(date.getUTCFullYear(), 0, 1))
  const weekNo = Math.ceil(((date.getTime() - yearStart.getTime()) / 86400000 + 1) / 7)
  return `${date.getUTCFullYear()}-W${String(weekNo).padStart(2, '0')}`
}

function hasStageWorkTag(tags: string[]): boolean {
  return tags.includes('stage:work')
}

export function buildStageReportData({
  workspaceId,
  from,
  to,
  actorUserId,
}: {
  workspaceId: string
  from: string
  to: string
  actorUserId: string
}): StageReport {
  const workspace = db.getGroupById(workspaceId)
  const actor = db.findUserById(actorUserId)
  const items = db.listPlanningForGroupRangeWithOwner(workspaceId, from, to)

  const byDate = new Map<string, StageReportItem[]>()
  const byWeek = new Map<string, StageReportWeekSummary>()
  let totalItems = 0
  let totalHours = 0
  let completedItems = 0
  let completedHours = 0
  let stageWorkHours = 0

  for (const it of items) {
    const tags = parseTags(it.tagsJson)
    const week = isoWeekKey(it.date)
    const hours = computeHours(it.start, it.end)
    const isStageWork = hasStageWorkTag(tags)
    const entry: StageReportItem = {
      date: it.date,
      week,
      title: it.title,
      status: it.status,
      hours,
      tags,
      isStageWork,
    }
    const list = byDate.get(it.date)
    if (list) list.push(entry)
    else byDate.set(it.date, [entry])

    totalItems += 1
    totalHours += hours
    if (it.status === 'done') {
      completedItems += 1
      completedHours += hours
    }
    if (isStageWork) stageWorkHours += hours

    const weekEntry = byWeek.get(week) || {
      week,
      totalItems: 0,
      totalHours: 0,
      statusCounts: { todo: 0, in_progress: 0, done: 0 },
    }
    weekEntry.totalItems += 1
    weekEntry.totalHours += hours
    weekEntry.statusCounts[it.status] += 1
    byWeek.set(week, weekEntry)
  }

  const days: StageReportDay[] = Array.from(byDate.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([date, itemsForDay]) => {
      const totalHours = itemsForDay.reduce((sum, i) => sum + i.hours, 0)
      return {
        date,
        items: itemsForDay,
        totalHours,
      }
    })

  const totalDays = days.length
  const weekSummaries = Array.from(byWeek.values()).sort((a, b) => a.week.localeCompare(b.week))
  const averageHoursPerDay = totalDays > 0 ? totalHours / totalDays : 0

  return {
    workspaceName: workspace?.name || 'Onbekende workspace',
    studentName: actor ? `${actor.firstName} ${actor.lastName}`.trim() : undefined,
    periodFrom: from,
    periodTo: to,
    exportDate: new Date().toISOString().slice(0, 10),
    days,
    weeks: weekSummaries,
    summary: {
      totalDays,
      totalItems,
      totalHours,
      completedItems,
      completedHours,
      stageWorkHours,
      averageHoursPerDay,
    },
  }
}
