import { db, type AppErrorLog } from '../db/db'

const SETTINGS_KEY = 'stageplanner.settings.v1'

function safeJson(meta: any) {
  try {
    return JSON.stringify(meta ?? {})
  } catch {
    return '{}'
  }
}

function getErrorLogSettings(): { enabled: boolean; retentionDays: number; maxEntries: number } {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY)
    if (!raw) return { enabled: true, retentionDays: 14, maxEntries: 500 }
    const parsed = JSON.parse(raw) as any
    const enabled = typeof parsed?.errorLoggingEnabled === 'boolean' ? parsed.errorLoggingEnabled : true
    const retentionDays = typeof parsed?.errorLogRetentionDays === 'number' && Number.isFinite(parsed.errorLogRetentionDays) ? parsed.errorLogRetentionDays : 14
    const maxEntries = typeof parsed?.errorLogMaxEntries === 'number' && Number.isFinite(parsed.errorLogMaxEntries) ? parsed.errorLogMaxEntries : 500
    return {
      enabled,
      retentionDays: Math.max(0, Math.min(365, Math.round(retentionDays))),
      maxEntries: Math.max(50, Math.min(5000, Math.round(maxEntries))),
    }
  } catch {
    return { enabled: true, retentionDays: 14, maxEntries: 500 }
  }
}

function normalizeError(err: unknown) {
  if (err instanceof Error) return { message: err.message || String(err), stack: err.stack }
  return { message: typeof err === 'string' ? err : safeJson(err), stack: undefined as string | undefined }
}

export async function logAppError(input: Omit<AppErrorLog, 'id' | 'createdAt' | 'metaJson'> & { meta?: any; createdAt?: number }) {
  try {
    const cfg = getErrorLogSettings()
    if (!cfg.enabled) return

    const entry: AppErrorLog = {
      createdAt: input.createdAt ?? Date.now(),
      level: input.level,
      source: input.source,
      message: input.message,
      stack: input.stack,
      metaJson: safeJson(input.meta),
    }
    await db.errors.add(entry)

    // Best-effort cleanup: retention + max entries.
    // (Do not crash app if cleanup fails.)
    const now = Date.now()
    if (cfg.retentionDays > 0) {
      const cutoff = now - cfg.retentionDays * 24 * 60 * 60 * 1000
      await db.errors.where('createdAt').below(cutoff).delete()
    }
    const total = await db.errors.count()
    if (total > cfg.maxEntries) {
      const extra = total - cfg.maxEntries
      const oldest = await db.errors.orderBy('createdAt').limit(extra).toArray()
      await db.errors.bulkDelete((oldest as AppErrorLog[]).map((entry) => entry.id!).filter(Boolean))
    }
  } catch {
    // never crash the app because logging failed
  }
}

export async function logError(source: AppErrorLog['source'], err: unknown, meta?: any) {
  const n = normalizeError(err)
  return logAppError({ level: 'error', source, message: n.message, stack: n.stack, meta })
}









