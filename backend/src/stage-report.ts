import type { DbPlanningItem } from './db'
import { db } from './db'

export type StageReportItem = {
  date: string
  title: string
  status: DbPlanningItem['status']
  hours: number
  tags: string[]
}

export type StageReportDay = {
  date: string
  items: StageReportItem[]
  totalHours: number
}

export type StageReportSummary = {
  totalDays: number
  totalHours: number
  averageHoursPerDay: number
}

export type StageReport = {
  workspaceName: string
  studentName?: string
  periodFrom: string
  periodTo: string
  exportDate: string
  days: StageReportDay[]
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
  for (const it of items) {
    const entry: StageReportItem = {
      date: it.date,
      title: it.title,
      status: it.status,
      hours: computeHours(it.start, it.end),
      tags: parseTags(it.tagsJson),
    }
    const list = byDate.get(it.date)
    if (list) list.push(entry)
    else byDate.set(it.date, [entry])
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
  const totalHours = days.reduce((sum, d) => sum + d.totalHours, 0)
  const averageHoursPerDay = totalDays > 0 ? totalHours / totalDays : 0

  return {
    workspaceName: workspace?.name || 'Onbekende workspace',
    studentName: actor ? `${actor.firstName} ${actor.lastName}`.trim() : undefined,
    periodFrom: from,
    periodTo: to,
    exportDate: new Date().toISOString().slice(0, 10),
    days,
    summary: {
      totalDays,
      totalHours,
      averageHoursPerDay,
    },
  }
}
