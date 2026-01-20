import crypto from 'node:crypto'
import { LRUCache } from 'lru-cache'
import type express from 'express'

type CacheEntry = {
  body: string
  etag: string
  contentType: string
  status: number
  createdAt: number
}

const ttlSecondsEnv = Number.parseInt(process.env.CACHE_TTL_SECONDS || '', 10)
const ttlSeconds = Number.isFinite(ttlSecondsEnv) && ttlSecondsEnv > 0 ? ttlSecondsEnv : 45

const cache = new LRUCache<string, CacheEntry>({
  max: 500,
  ttl: ttlSeconds * 1000,
})

const workspaceIndex = new Map<string, Set<string>>()

function logCache(message: string, key: string) {
  if (process.env.NODE_ENV !== 'production') {
    // eslint-disable-next-line no-console
    console.log(`[cache] ${message} ${key}`)
  }
}

function createEtag(body: string) {
  const hash = crypto.createHash('sha256').update(body).digest('hex')
  return `"${hash}"`
}

function etagMatches(headerValue: string | undefined, etag: string) {
  if (!headerValue) return false
  const parts = headerValue.split(',').map((p) => p.trim())
  return parts.includes(etag)
}

function setCacheHeaders(res: express.Response, etag: string) {
  res.setHeader('Cache-Control', 'private, max-age=0')
  res.setHeader('ETag', etag)
}

function indexKey(workspaceId: string, key: string) {
  const set = workspaceIndex.get(workspaceId) || new Set<string>()
  set.add(key)
  workspaceIndex.set(workspaceId, set)
}

export function buildCacheKey(opts: {
  endpoint: string
  workspaceId: string
  query?: Record<string, string | undefined>
}) {
  const params = new URLSearchParams()
  const entries = Object.entries(opts.query || {}).filter(([, v]) => v != null && v !== '')
  entries.sort(([a], [b]) => a.localeCompare(b))
  for (const [k, v] of entries) {
    params.set(k, String(v))
  }
  const qs = params.toString()
  return `${opts.endpoint}|workspace=${opts.workspaceId}${qs ? `|${qs}` : ''}`
}

export function maybeHandleCachedResponse(req: express.Request, res: express.Response, key: string) {
  const entry = cache.get(key)
  if (!entry) {
    logCache('MISS', key)
    return false
  }
  logCache('HIT', key)
  setCacheHeaders(res, entry.etag)
  if (etagMatches(req.get('if-none-match') || undefined, entry.etag)) {
    res.status(304).end()
    return true
  }
  res.status(entry.status).type(entry.contentType).send(entry.body)
  return true
}

export function storeCacheAndSend(
  req: express.Request,
  res: express.Response,
  key: string,
  workspaceId: string,
  payload: unknown,
) {
  const body = JSON.stringify(payload)
  const etag = createEtag(body)
  const entry: CacheEntry = {
    body,
    etag,
    contentType: 'application/json',
    status: 200,
    createdAt: Date.now(),
  }
  cache.set(key, entry)
  indexKey(workspaceId, key)
  setCacheHeaders(res, etag)
  res.status(200).type('application/json').send(body)
}

export function invalidateWorkspaceCache(workspaceId: string) {
  const keys = workspaceIndex.get(workspaceId)
  if (!keys) return
  for (const key of keys) {
    cache.delete(key)
  }
  workspaceIndex.delete(workspaceId)
  logCache('INVALIDATE', `workspace=${workspaceId}`)
}

export function getCacheTtlSeconds() {
  return ttlSeconds
}
