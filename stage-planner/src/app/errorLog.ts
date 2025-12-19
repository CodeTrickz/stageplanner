import { db, type AppErrorLog } from '../db/db'

function safeJson(meta: any) {
  try {
    return JSON.stringify(meta ?? {})
  } catch {
    return '{}'
  }
}

function normalizeError(err: unknown) {
  if (err instanceof Error) return { message: err.message || String(err), stack: err.stack }
  return { message: typeof err === 'string' ? err : safeJson(err), stack: undefined as string | undefined }
}

export async function logAppError(input: Omit<AppErrorLog, 'id' | 'createdAt' | 'metaJson'> & { meta?: any; createdAt?: number }) {
  try {
    const entry: AppErrorLog = {
      createdAt: input.createdAt ?? Date.now(),
      level: input.level,
      source: input.source,
      message: input.message,
      stack: input.stack,
      metaJson: safeJson(input.meta),
    }
    await db.errors.add(entry)
  } catch {
    // never crash the app because logging failed
  }
}

export async function logError(source: AppErrorLog['source'], err: unknown, meta?: any) {
  const n = normalizeError(err)
  return logAppError({ level: 'error', source, message: n.message, stack: n.stack, meta })
}







