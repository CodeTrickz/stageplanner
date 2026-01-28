import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client'

// Central Prometheus registry shared across server + db layer
export const register = new Registry()
collectDefaultMetrics({ register })

export const httpRequestDurationSeconds = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status'] as const,
  registers: [register],
})

export const httpRequestsTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status'] as const,
  registers: [register],
})

export const httpErrorsTotal = new Counter({
  name: 'http_errors_total',
  help: 'Total number of HTTP requests with status >= 400',
  labelNames: ['method', 'route', 'status'] as const,
  registers: [register],
})

export const sseActiveConnections = new Gauge({
  name: 'sse_active_connections',
  help: 'Number of active SSE connections',
  registers: [register],
})

export const sseDisconnectsTotal = new Counter({
  name: 'sse_disconnects_total',
  help: 'Total number of SSE disconnects',
  registers: [register],
})

export const dbErrorsTotal = new Counter({
  name: 'db_errors_total',
  help: 'Total number of database errors',
  registers: [register],
})

export const dbQueryDurationSeconds = new Histogram({
  name: 'db_query_duration_seconds',
  help: 'Duration of database queries in seconds',
  labelNames: ['op', 'kind'] as const,
  registers: [register],
})

export function classifySqlKind(sql: string): string {
  const first = String(sql || '').trim().split(/\s+/)[0]?.toLowerCase()
  if (!first) return 'unknown'
  if (first === 'select') return 'select'
  if (first === 'insert') return 'insert'
  if (first === 'update') return 'update'
  if (first === 'delete') return 'delete'
  if (first === 'pragma') return 'pragma'
  return first
}

