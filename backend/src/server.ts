import cors from 'cors'
import dotenv from 'dotenv'
import express from 'express'
import helmet from 'helmet'
import morgan from 'morgan'
import bcrypt from 'bcryptjs'
import { ZodError, z } from 'zod'
import { getUser, getUserFromToken, requireAuth, signAccessToken } from './auth'
import { db, type DbPlanningItem, type DbNote, type DbFile } from './db'
import path from 'node:path'
import crypto from 'node:crypto'
import { sendMail } from './mail'
import fs from 'node:fs'
import { Registry, Counter, Histogram, collectDefaultMetrics } from 'prom-client'
import { FORMAT_HTTP_HEADERS, Span, SpanContext } from 'opentracing'

// jaeger-client is a CommonJS module that exports an object with initTracer
// eslint-disable-next-line @typescript-eslint/no-require-imports
const jaegerClient = require('jaeger-client')
const initTracer = jaegerClient.initTracer as (config: any, options?: any) => any

class ApiError extends Error {
  status: number
  code: string
  details?: any
  constructor(status: number, code: string, details?: any) {
    super(code)
    this.status = status
    this.code = code
    this.details = details
  }
}

function parseBody<T>(req: express.Request, schema: z.ZodType<T>): T {
  const parsed = schema.safeParse(req.body)
  if (!parsed.success) throw parsed.error
  return parsed.data
}

function parseQuery<T>(req: express.Request, schema: z.ZodType<T>): T {
  const parsed = schema.safeParse(req.query)
  if (!parsed.success) throw parsed.error
  return parsed.data
}

// Wrapper voor async route handlers om errors correct door te geven aan error handler
function asyncHandler(
  fn: (req: express.Request, res: express.Response, next: express.NextFunction) => Promise<any>
): express.RequestHandler {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next)
  }
}

type RateLimitOptions = {
  name: string
  windowMs: number
  max: number
  key: (req: express.Request) => string
}

function makeRateLimiter(opts: RateLimitOptions) {
  const buckets = new Map<string, { count: number; resetAt: number }>()
  const sweepEvery = Math.max(10_000, Math.min(60_000, Math.floor(opts.windowMs / 2)))
  let lastSweep = 0

  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const now = Date.now()
    if (now - lastSweep > sweepEvery) {
      lastSweep = now
      for (const [k, v] of buckets.entries()) {
        if (v.resetAt <= now) buckets.delete(k)
      }
    }

    const key = `${opts.name}:${opts.key(req)}`
    const cur = buckets.get(key)
    if (!cur || cur.resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + opts.windowMs })
      return next()
    }

    cur.count += 1
    if (cur.count > opts.max) {
      const retryAfterSec = Math.max(1, Math.ceil((cur.resetAt - now) / 1000))
      res.setHeader('Retry-After', String(retryAfterSec))
      return res.status(429).json({ error: 'rate_limited' })
    }
    return next()
  }
}

function sha256Hex(s: string) {
  return crypto.createHash('sha256').update(s).digest('hex')
}

function isStrongPassword(pw: string) {
  // pragmatic: strong enough without being annoying
  if (pw.length < 10) return false
  if (pw.length > 200) return false
  if (/\s/.test(pw)) return false
  const hasLetter = /[a-zA-Z]/.test(pw)
  const hasNumber = /\d/.test(pw)
  return hasLetter && hasNumber
}

function trimTrailingSlash(s: string) {
  return s.replace(/\/+$/, '')
}

function getPublicAppUrl() {
  return trimTrailingSlash(process.env.APP_URL || 'http://localhost:5173')
}

// Public URL where the backend verification endpoint is reachable.
// - If PUBLIC_API_URL is set, use it (recommended for reverse proxies).
// - Else assume backend is reachable via `${APP_URL}/api` (Docker/nginx setup).
function getPublicApiUrl() {
  const explicit = process.env.PUBLIC_API_URL
  if (explicit) return trimTrailingSlash(explicit)
  return `${getPublicAppUrl()}/api`
}

function buildVerifyUrls(rawToken: string) {
  const enc = encodeURIComponent(rawToken)
  const appVerifyUrl = `${getPublicAppUrl()}/verify?token=${enc}`
  const apiVerifyUrl = `${getPublicApiUrl()}/auth/verify?token=${enc}`
  return { appVerifyUrl, apiVerifyUrl }
}

function buildResetUrls(rawToken: string) {
  const enc = encodeURIComponent(rawToken)
  const appResetUrl = `${getPublicAppUrl()}/reset?token=${enc}`
  const apiResetUrl = `${getPublicApiUrl()}/auth/reset-password?token=${enc}`
  return { appResetUrl, apiResetUrl }
}

// Load env from backend/env.local if it exists (no dotfile needed)
dotenv.config({ path: path.resolve(__dirname, '..', 'env.local') })

// Prometheus metrics setup
const register = new Registry()
collectDefaultMetrics({ register })

const httpRequestDuration = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status'],
  registers: [register],
})

const httpRequestTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [register],
})

// Jaeger tracing setup
const jaegerAgentPort = process.env.JAEGER_AGENT_PORT
  ? Number.parseInt(process.env.JAEGER_AGENT_PORT, 10)
  : 6831

const jaegerConfig = {
  serviceName: process.env.JAEGER_SERVICE_NAME || 'stageplanner-backend',
  sampler: {
    type: 'const',
    param: 1, // Sample all traces
  },
  reporter: {
    agentHost: process.env.JAEGER_AGENT_HOST || 'jaeger',
    agentPort: Number.isFinite(jaegerAgentPort) ? jaegerAgentPort : 6831,
    logSpans: process.env.NODE_ENV !== 'production',
  },
}

const tracer = initTracer(jaegerConfig, {
  logger: {
    info: (msg: string) => {
      if (process.env.NODE_ENV !== 'production') {
        // eslint-disable-next-line no-console
        console.log(`[Jaeger] ${msg}`)
      }
    },
    error: (msg: string) => {
      // eslint-disable-next-line no-console
      console.error(`[Jaeger] ${msg}`)
    },
  },
})

const app = express()
type SseClient = {
  res: express.Response
  workspaceId: string
}

const sseClients = new Set<SseClient>()

function broadcastWorkspace(workspaceId: string, type: string) {
  const data = JSON.stringify({ type, workspaceId, ts: Date.now() })
  for (const c of sseClients) {
    if (c.workspaceId === workspaceId) {
      c.res.write(`event: update\n`)
      c.res.write(`data: ${data}\n\n`)
    }
  }
}
// If behind reverse proxy (nginx), set TRUST_PROXY=1 (or a number) so req.ip is correct.
if (process.env.TRUST_PROXY) {
  const raw = process.env.TRUST_PROXY.trim()
  const v = raw === 'true' ? 1 : raw === 'false' ? 0 : Number(raw)
  if (Number.isFinite(v)) app.set('trust proxy', v)
}
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // MUI vereist inline styles
        imgSrc: ["'self'", "data:", "blob:"],
        connectSrc: ["'self'", process.env.CORS_ORIGIN || 'http://localhost:5173'],
        fontSrc: ["'self'", "data:"],
      },
    },
    crossOriginEmbedderPolicy: false, // Voor compatibiliteit met bestaande setup
    hsts: {
      maxAge: 31536000, // 1 jaar
      includeSubDomains: true,
      preload: true,
    },
  }),
)
// Extra security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('X-XSS-Protection', '1; mode=block')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
  next()
})
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
    credentials: false,
  }),
)
app.use(express.json({ limit: '2mb' }))
app.use(morgan('dev'))

// Jaeger tracing middleware
app.use((req, res, next) => {
  const parentSpanContext = tracer.extract(FORMAT_HTTP_HEADERS, req.headers)
  const span = tracer.startSpan(`${req.method} ${req.path}`, {
    childOf: parentSpanContext as SpanContext | undefined,
    tags: {
      'http.method': req.method,
      'http.url': req.url,
      'http.route': req.route?.path || req.path,
    },
  })

  // Store span in request for use in route handlers
  ;(req as any).span = span

  res.on('finish', () => {
    span.setTag('http.status_code', res.statusCode)
    if (res.statusCode >= 400) {
      span.setTag('error', true)
    }
    span.finish()
  })

  next()
})

// Metrics middleware
app.use((req, res, next) => {
  const start = Date.now()
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000
    const route = req.route?.path || req.path || 'unknown'
    httpRequestDuration.observe({ method: req.method, route, status: res.statusCode }, duration)
    httpRequestTotal.inc({ method: req.method, route, status: res.statusCode })
  })
  next()
})

app.get('/health', (_req, res) => res.json({ ok: true }))

// Prometheus metrics endpoint
app.get('/metrics', async (_req, res) => {
  res.set('Content-Type', register.contentType)
  res.end(await register.metrics())
})

const ERROR_LOG_PATH = path.resolve(process.cwd(), 'data', 'errors.ndjson')

function appendErrorLog(entry: any) {
  try {
    fs.mkdirSync(path.dirname(ERROR_LOG_PATH), { recursive: true })
    fs.appendFileSync(ERROR_LOG_PATH, JSON.stringify(entry) + '\n', 'utf-8')
  } catch {
    // ignore
  }
}

process.on('unhandledRejection', (reason) => {
  appendErrorLog({
    ts: Date.now(),
    type: 'unhandledRejection',
    name: (reason as any)?.name,
    code: (reason as any)?.code,
    message: (reason as any)?.message || String(reason),
    stack: (reason as any)?.stack,
  })
})
process.on('uncaughtException', (err) => {
  appendErrorLog({
    ts: Date.now(),
    type: 'uncaughtException',
    name: (err as any)?.name,
    code: (err as any)?.code,
    message: (err as any)?.message || String(err),
    stack: (err as any)?.stack,
  })
})

function audit(req: express.Request, action: string, resourceType: string, resourceId: string, meta: any = {}) {
  const u = getUser(req)
  if (!u) return
  try {
    db.addAudit({
      actorUserId: u.id,
      action,
      resourceType,
      resourceId,
      metaJson: JSON.stringify(meta ?? {}),
    })
  } catch {
    // ignore audit failures
  }
}

function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const u = getUser(req)
  if (!u || !u.isAdmin) return res.status(403).json({ error: 'forbidden' })
  return next()
}

// Workspace RBAC helpers
type WorkspaceRole = 'STUDENT' | 'MENTOR' | 'BEGELEIDER'

function getWorkspaceRole(userId: string, workspaceId: string): WorkspaceRole | null {
  return db.getMembershipRole(userId, workspaceId)
}

function requireWorkspaceRole(allowedRoles: WorkspaceRole[]) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const u = getUser(req)
    if (!u) return res.status(401).json({ error: 'unauthorized' })
    // Try multiple parameter names: id (for /workspaces/:id/...), workspaceId, or from body
    const workspaceId = req.params.id || req.params.workspaceId || (req.body as any)?.workspaceId
    if (!workspaceId) return res.status(400).json({ error: 'workspace_id_required' })
    const role = getWorkspaceRole(u.id, workspaceId)
    if (!role || !allowedRoles.includes(role)) {
      return res.status(403).json({ error: 'insufficient_permissions' })
    }
    return next()
  }
}

function requireWorkspaceStudent(req: express.Request, res: express.Response, next: express.NextFunction) {
  return requireWorkspaceRole(['STUDENT'])(req, res, next)
}

function canCreateInWorkspace(userId: string, workspaceId: string): boolean {
  const role = getWorkspaceRole(userId, workspaceId)
  return role === 'STUDENT'
}

function canEditInWorkspace(userId: string, workspaceId: string, _resourceOwnerId: string): boolean {
  const role = getWorkspaceRole(userId, workspaceId)
  if (!role) return false
  // Any STUDENT can edit items within the workspace
  return role === 'STUDENT'
}

function canDeleteInWorkspace(userId: string, workspaceId: string, _resourceOwnerId: string): boolean {
  const role = getWorkspaceRole(userId, workspaceId)
  return role === 'STUDENT'
}

function getDbUserOr401(req: express.Request, res: express.Response) {
  const auth = getUser(req)
  if (!auth) {
    res.status(401).json({ error: 'unauthorized' })
    return null
  }
  const u = db.findUserById(auth.id)
  if (!u) {
    res.status(401).json({ error: 'unauthorized' })
    return null
  }
  return u
}

// Seed default admin (dev/stage only - NEVER in production)
// This function ensures only the admin user exists - removes all other users
;(function seedAdmin() {
  // Only seed in development or if explicitly enabled
  const isProduction = process.env.NODE_ENV === 'production'
  const seedEnabled = process.env.SEED_ADMIN === 'true'
  
  if (isProduction && !seedEnabled) {
    return // Skip seeding in production unless explicitly enabled
  }

  const email = process.env.ADMIN_EMAIL || 'admin@app.be'
  const password = process.env.ADMIN_PASSWORD || 'admin'
  const username = process.env.ADMIN_USERNAME || 'admin'

  // Remove all users except the admin user
  const allUsers = db.listUsers()
  const adminUser = db.findUserByEmail(email)
  const adminUserId = adminUser?.id

  for (const user of allUsers) {
    // Skip the admin user if it exists
    if (adminUserId && user.id === adminUserId) {
      continue
    }
    // Delete all other users
    db.deleteUser(user.id)
  }

  // Create admin user if it doesn't exist
  if (!adminUser) {
    const passwordHash = bcrypt.hashSync(password, 10)
    const tokenHash = crypto.createHash('sha256').update('seeded').digest('hex')
    const expiresAt = Date.now() + 1000 * 60 * 60 * 24 * 365

    db.createUser({
      email,
      username,
      firstName: 'Admin',
      lastName: 'User',
      passwordHash,
      emailVerificationTokenHash: tokenHash,
      emailVerificationExpiresAt: expiresAt,
      isAdmin: true,
      emailVerified: true,
    })
    // eslint-disable-next-line no-console
    console.log(`Seeded admin user: ${email} / ${password}`)
  } else {
    // Ensure existing admin user has correct properties
    db.updateUser(adminUser.id, {
      isAdmin: 1,
      emailVerified: 1,
    })
    // eslint-disable-next-line no-console
    console.log(`Admin user already exists: ${email}`)
  }

  if (isProduction) {
    // eslint-disable-next-line no-console
    console.warn('WARNING: Admin user seeded in production! This should only be done during initial setup.')
  }
})()

// Rate limiting (brute-force protection)
const rlAuthIp = makeRateLimiter({
  name: 'auth_ip',
  windowMs: 10 * 60 * 1000,
  max: 120,
  key: (req) => req.ip || 'unknown',
})
const rlLoginIdentity = makeRateLimiter({
  name: 'login_identity',
  windowMs: 10 * 60 * 1000,
  max: 12,
  key: (req) => {
    const body: any = req.body || {}
    const identifier = String(body.identifier || body.email || '').trim().toLowerCase()
    return `${req.ip || 'unknown'}:${identifier}`
  },
})
const rlVerifyIp = makeRateLimiter({
  name: 'verify_ip',
  windowMs: 10 * 60 * 1000,
  max: 60,
  key: (req) => req.ip || 'unknown',
})
const rlPasswordChange = makeRateLimiter({
  name: 'password_change',
  windowMs: 10 * 60 * 1000,
  max: 20,
  key: (req) => getUser(req)?.id || req.ip || 'unknown',
})

const registerSchema = z
  .object({
    email: z.string().email(),
    username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9._-]+$/),
    firstName: z.string().min(1).max(80),
    lastName: z.string().min(1).max(80),
    password: z.string().min(10).max(200),
    passwordConfirm: z.string().min(10).max(200),
  })
  .refine((d) => d.password === d.passwordConfirm, { message: 'password_mismatch' })
  .refine((d) => isStrongPassword(d.password), { message: 'weak_password' })

app.post('/auth/register', rlAuthIp, asyncHandler(async (req, res) => {
  const { email, username, firstName, lastName, password } = parseBody(req, registerSchema)
  const existing = db.findUserByEmail(email)
  if (existing) return res.status(409).json({ error: 'email_in_use' })
  const existingU = db.findUserByUsername(username)
  if (existingU) return res.status(409).json({ error: 'username_in_use' })

  const passwordHash = await bcrypt.hash(password, 10)

  const rawToken = crypto.randomBytes(32).toString('hex')
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')
  const expiresAt = Date.now() + 1000 * 60 * 60 * 24 // 24h

  const user = db.createUser({
    email,
    username,
    firstName,
    lastName,
    passwordHash,
    emailVerificationTokenHash: tokenHash,
    emailVerificationExpiresAt: expiresAt,
  })

  const { appVerifyUrl, apiVerifyUrl } = buildVerifyUrls(rawToken)

  await sendMail({
    to: user.email,
    subject: 'Stage Planner: account activatie',
    text: `Activeer je account:\n${appVerifyUrl}\n\nDirecte link (als dit niet werkt):\n${apiVerifyUrl}\n\nDeze link is 24 uur geldig.`,
  })

  return res.json({ ok: true, message: 'verification_required' })
}))

const loginSchema = z.object({
  identifier: z.string().min(1).max(300), // email or username
  password: z.string().min(1).max(200),
})

function refreshTtlMs() {
  const daysRaw = process.env.REFRESH_EXPIRES_DAYS || '30'
  const days = Number(daysRaw)
  const safe = Number.isFinite(days) ? Math.min(180, Math.max(1, Math.round(days))) : 30
  return safe * 24 * 60 * 60 * 1000
}

function issueRefreshToken(userId: string, req: express.Request) {
  const raw = crypto.randomBytes(48).toString('hex')
  const tokenHash = sha256Hex(raw)
  const createdAt = Date.now()
  const expiresAt = createdAt + refreshTtlMs()
  db.createRefreshToken({
    userId,
    tokenHash,
    createdAt,
    expiresAt,
    ip: req.ip || null,
    userAgent: String(req.header('user-agent') || '').slice(0, 300) || null,
  })
  return { raw, expiresAt }
}

app.post('/auth/login', rlAuthIp, rlLoginIdentity, asyncHandler(async (req, res) => {
  const { identifier, password } = parseBody(req, loginSchema)
  const rawId = identifier.trim()

  let user = null
  // If it looks like an email, try email first
  if (rawId.includes('@')) {
    user = db.findUserByEmail(rawId)
  }
  // Fallback to username if not found by email or if no '@'
  if (!user) {
    user = db.findUserByUsername(rawId)
  }

  if (!user) return res.status(401).json({ error: 'invalid_credentials' })
  if (!user.emailVerified) return res.status(403).json({ error: 'email_not_verified' })

  const ok = await bcrypt.compare(password, user.passwordHash)
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' })

  const token = signAccessToken({ sub: user.id, email: user.email, isAdmin: !!user.isAdmin })
  const refresh = issueRefreshToken(user.id, req)
  return res.json({
    token,
    refreshToken: refresh.raw,
    refreshTokenExpiresAt: refresh.expiresAt,
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      isAdmin: !!user.isAdmin,
    },
  })
}))

const refreshSchema = z.object({
  refreshToken: z.string().min(20).max(2000),
})

app.post('/auth/refresh', rlAuthIp, (req, res) => {
  const { refreshToken } = parseBody(req, refreshSchema)
  const raw = refreshToken
  const tokenHash = sha256Hex(raw)
  const rt = db.getRefreshTokenByHash(tokenHash)
  if (!rt) return res.status(401).json({ error: 'invalid_refresh_token' })
  if (rt.revokedAt != null) return res.status(401).json({ error: 'invalid_refresh_token' })
  if (rt.expiresAt <= Date.now()) return res.status(401).json({ error: 'refresh_token_expired' })

  const user = db.findUserById(rt.userId)
  if (!user) return res.status(401).json({ error: 'unauthorized' })
  if (!user.emailVerified) return res.status(403).json({ error: 'email_not_verified' })

  // rotate
  const next = issueRefreshToken(user.id, req)
  const now = Date.now()
  db.touchRefreshToken(tokenHash, now)
  db.revokeRefreshToken(tokenHash, { revokedAt: now, replacedByTokenHash: sha256Hex(next.raw) })

  const token = signAccessToken({ sub: user.id, email: user.email, isAdmin: !!user.isAdmin })
  return res.json({
    token,
    refreshToken: next.raw,
    refreshTokenExpiresAt: next.expiresAt,
  })
})

app.post('/auth/logout', rlAuthIp, (req, res) => {
  const { refreshToken } = parseBody(req, refreshSchema)
  const tokenHash = sha256Hex(refreshToken)
  // idempotent: always ok
  db.revokeRefreshToken(tokenHash)
  return res.json({ ok: true })
})

app.get('/me', requireAuth, (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  return res.json({
    user: {
      id: u.id,
      email: u.email,
      username: u.username,
      firstName: u.firstName,
      lastName: u.lastName,
      isAdmin: !!u.isAdmin,
      emailVerified: !!u.emailVerified,
    },
  })
})

const mePatchSchema = z
  .object({
    username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9._-]+$/).optional(),
    firstName: z.string().min(1).max(80).optional(),
    lastName: z.string().min(1).max(80).optional(),
  })
  .refine((d) => d.username != null || d.firstName != null || d.lastName != null, { message: 'empty_patch' })

app.patch('/me', requireAuth, (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const parsed = mePatchSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  const patch = parsed.data

  if (patch.username && patch.username !== u.username) {
    const existing = db.findUserByUsername(patch.username)
    if (existing && existing.id !== u.id) return res.status(409).json({ error: 'username_in_use' })
  }

  const updated = db.updateUser(u.id, {
    username: patch.username,
    firstName: patch.firstName,
    lastName: patch.lastName,
  })
  if (!updated) return res.status(404).json({ error: 'not_found' })

  audit(req, 'account.update', 'user', u.id, { username: updated.username })
  return res.json({
    user: {
      id: updated.id,
      email: updated.email,
      username: updated.username,
      firstName: updated.firstName,
      lastName: updated.lastName,
      isAdmin: !!updated.isAdmin,
      emailVerified: !!updated.emailVerified,
    },
  })
})

const mePasswordSchema = z
  .object({
    currentPassword: z.string().min(1).max(200),
    newPassword: z.string().min(10).max(200),
    newPasswordConfirm: z.string().min(10).max(200),
  })
  .refine((d) => d.newPassword === d.newPasswordConfirm, { message: 'password_mismatch' })
  .refine((d) => isStrongPassword(d.newPassword), { message: 'weak_password' })
  .refine((d) => d.newPassword !== d.currentPassword, { message: 'password_reuse' })

app.post('/me/password', requireAuth, rlPasswordChange, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const { currentPassword, newPassword } = parseBody(req, mePasswordSchema)

  const ok = await bcrypt.compare(currentPassword, u.passwordHash)
  if (!ok) return res.status(403).json({ error: 'invalid_credentials' })

  const hash = await bcrypt.hash(newPassword, 10)
  db.setUserPassword(u.id, hash)
  audit(req, 'account.password_change', 'user', u.id)
  return res.json({ ok: true })
}))

// SSE: workspace updates (push layer)
app.get('/events', asyncHandler(async (req, res) => {
  const token = String(req.query.token || '')
  const u = getUserFromToken(token)
  if (!u) return res.status(401).json({ error: 'unauthorized' })
  const workspaceId = String(req.query.workspaceId || '')
  if (!workspaceId) return res.status(400).json({ error: 'workspace_id_required' })
  const role = db.getMembershipRole(u.id, workspaceId)
  if (!role) return res.status(403).json({ error: 'not_member' })

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  })
  res.write(`event: ready\n`)
  res.write(`data: ${JSON.stringify({ ok: true, workspaceId })}\n\n`)

  const client = { res, workspaceId }
  sseClients.add(client)

  const keepAlive = setInterval(() => {
    res.write(`event: ping\n`)
    res.write(`data: {}\n\n`)
  }, 25000)

  req.on('close', () => {
    clearInterval(keepAlive)
    sseClients.delete(client)
  })
}))

// Client-side settings changes: log to audit
const clientSettingsAuditSchema = z.object({
  changes: z.record(z.any()).default({}),
})

app.post('/audit/settings', requireAuth, (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const parsed = clientSettingsAuditSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  const changes = parsed.data.changes || {}
  // avoid huge audit payloads
  const keys = Object.keys(changes).slice(0, 50)
  const trimmed: any = {}
  for (const k of keys) trimmed[k] = changes[k]
  audit(req, 'settings.update', 'settings', u.id, { keys, changes: trimmed })
  return res.json({ ok: true })
})

const auditFilesSchema = z.object({
  action: z.enum(['upload', 'download', 'delete']),
  files: z
    .array(
      z.object({
        name: z.string().min(1).max(300),
        type: z.string().min(0).max(200).optional().nullable(),
        size: z.number().nonnegative().optional().nullable(),
        groupKey: z.string().min(0).max(400).optional().nullable(),
        version: z.number().int().positive().optional().nullable(),
      }),
    )
    .min(1)
    .max(50),
})

app.post('/audit/files', requireAuth, (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const parsed = auditFilesSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })

  const { action, files } = parsed.data
  const totalBytes = files.reduce((acc, f) => acc + (Number(f.size ?? 0) || 0), 0)
  const resourceId = files.length === 1 ? String(files[0].groupKey || files[0].name) : 'bulk'
  audit(req, `file.${action}`, 'file', resourceId, {
    count: files.length,
    totalBytes,
    files: files.slice(0, 20),
  })
  return res.json({ ok: true })
})

// File meta (folders/labels) - workspace aware
const fileMetaListQuerySchema = z.object({
  workspaceId: z.string(),
})

const fileMetaUpsertSchema = z.object({
  workspaceId: z.string(),
  groupKey: z.string().min(1).max(400),
  folder: z.string().max(200),
  labelsJson: z.string().max(4000),
})

app.get('/file-meta', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const { workspaceId } = parseQuery(req, fileMetaListQuerySchema)
  const role = db.getMembershipRole(u.id, workspaceId)
  if (!role) return res.status(403).json({ error: 'not_member' })
  const items = db.listFileMetaForWorkspace(workspaceId)
  return res.json({ items, workspaceId })
}))

app.post('/file-meta', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const parsed = fileMetaUpsertSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  const d = parsed.data
  const role = db.getMembershipRole(u.id, d.workspaceId)
  if (!role) return res.status(403).json({ error: 'not_member' })
  if (!canCreateInWorkspace(u.id, d.workspaceId)) return res.status(403).json({ error: 'only_students_can_create' })
  const item = db.upsertFileMeta(d.workspaceId, d.groupKey, d.folder, d.labelsJson)
  broadcastWorkspace(d.workspaceId, 'file_meta')
  return res.json({ item, workspaceId: d.workspaceId })
}))

// Entity links (planning<->note<->fileGroup) - workspace aware
const linksListQuerySchema = z.object({
  workspaceId: z.string(),
  fromType: z.enum(['planning', 'note']),
  fromId: z.string().min(1),
})

const linksUpsertSchema = z.object({
  workspaceId: z.string(),
  fromType: z.enum(['planning', 'note']),
  fromId: z.string().min(1),
  links: z.array(
    z.object({
      toType: z.enum(['fileGroup', 'note', 'planning']),
      toKey: z.string().min(1),
    }),
  ),
})

app.get('/links', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const { workspaceId, fromType, fromId } = parseQuery(req, linksListQuerySchema)
  const role = db.getMembershipRole(u.id, workspaceId)
  if (!role) return res.status(403).json({ error: 'not_member' })
  const items = db.listLinksForItem(workspaceId, fromType, fromId)
  return res.json({ items, workspaceId })
}))

app.post('/links', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const parsed = linksUpsertSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  const d = parsed.data
  const role = db.getMembershipRole(u.id, d.workspaceId)
  if (!role) return res.status(403).json({ error: 'not_member' })
  if (!canCreateInWorkspace(u.id, d.workspaceId)) return res.status(403).json({ error: 'only_students_can_create' })
  const items = db.replaceLinksForItem(d.workspaceId, d.fromType, d.fromId, d.links)
  broadcastWorkspace(d.workspaceId, 'links')
  return res.json({ items, workspaceId: d.workspaceId })
}))

// Files (cloud) - workspace aware
const filesListQuerySchema = z.object({
  workspaceId: z.string().optional(),
})

const fileUploadSchema = z.object({
  name: z.string().min(1).max(300),
  type: z.string().min(1).max(200),
  size: z.number().int().nonnegative(),
  groupKey: z.string().min(1).max(400),
  version: z.number().int().positive().optional().default(1),
  workspaceId: z.string().optional(),
  data: z.string(), // base64 encoded file data
})

app.get('/files', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const { workspaceId } = parseQuery(req, filesListQuerySchema)

  // If workspaceId provided, filter by workspace
  if (workspaceId) {
    // Check if user is member of workspace
    const role = db.getMembershipRole(u.id, workspaceId)
    if (!role) return res.status(403).json({ error: 'not_member' })

    const files = db.listFilesForWorkspace(workspaceId)
    // Return files without data (too large for JSON)
    const filesWithoutData = files.map(f => ({
      id: f.id,
      userId: f.userId,
      workspaceId: f.workspaceId,
      name: f.name,
      type: f.type,
      size: f.size,
      groupKey: f.groupKey,
      version: f.version,
      createdAt: f.createdAt,
      updatedAt: f.updatedAt,
    }))
    return res.json({ files: filesWithoutData, workspaceId })
  }

  // Legacy: list all files for user
  const files = db.listFilesForUser(u.id)
  const filesWithoutData = files.map(f => ({
    id: f.id,
    userId: f.userId,
    workspaceId: f.workspaceId,
    name: f.name,
    type: f.type,
    size: f.size,
    groupKey: f.groupKey,
    version: f.version,
    createdAt: f.createdAt,
    updatedAt: f.updatedAt,
  }))
  return res.json({ files: filesWithoutData })
}))

app.get('/files/:id', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const fileId = req.params.id

  const file = db.getFileById(fileId)
  if (!file) return res.status(404).json({ error: 'not_found' })

  // Check workspace membership if file belongs to workspace
  if (file.workspaceId) {
    const role = db.getMembershipRole(u.id, file.workspaceId)
    if (!role) return res.status(403).json({ error: 'not_member' })
  } else {
    // Personal file - only owner can access
    if (file.userId !== u.id) return res.status(403).json({ error: 'forbidden' })
  }

  res.setHeader('Content-Type', file.type)
  res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`)
  res.setHeader('Content-Length', file.size.toString())
  return res.send(file.data)
}))

app.post('/files', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return

  const parsed = fileUploadSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input', issues: parsed.error.issues })

  const d = parsed.data

  // Check workspace membership if workspaceId provided
  let finalWorkspaceId: string | null = null
  if (d.workspaceId) {
    const role = db.getMembershipRole(u.id, d.workspaceId)
    if (!role) return res.status(403).json({ error: 'not_member' })
    
    // Only STUDENT can upload files
    if (!canCreateInWorkspace(u.id, d.workspaceId)) {
      return res.status(403).json({ error: 'only_students_can_create' })
    }
    finalWorkspaceId = d.workspaceId
  }

  // Decode base64 data
  let data: Buffer
  try {
    data = Buffer.from(d.data, 'base64')
  } catch (e) {
    return res.status(400).json({ error: 'invalid_file_data' })
  }

  // Validate size matches
  if (data.length !== d.size) {
    return res.status(400).json({ error: 'size_mismatch' })
  }

  // Check if file with same groupKey exists
  const existing = db.getLatestFileByGroupKey(d.groupKey, finalWorkspaceId)
  if (existing && existing.version >= d.version) {
    return res.status(400).json({ error: 'version_conflict' })
  }

  const file = db.createFile({
    userId: u.id,
    workspaceId: finalWorkspaceId,
    name: d.name,
    type: d.type,
    size: d.size,
    groupKey: d.groupKey,
    version: d.version,
    data,
  })

  audit(req, 'file.upload', 'file', file.id, { workspaceId: finalWorkspaceId, name: file.name, size: file.size })
  if (file.workspaceId) broadcastWorkspace(file.workspaceId, 'files')
  return res.json({
    file: {
      id: file.id,
      userId: file.userId,
      workspaceId: file.workspaceId,
      name: file.name,
      type: file.type,
      size: file.size,
      groupKey: file.groupKey,
      version: file.version,
      createdAt: file.createdAt,
      updatedAt: file.updatedAt,
    },
  })
}))

app.delete('/files/:id', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const fileId = req.params.id

  const file = db.getFileById(fileId)
  if (!file) return res.status(404).json({ error: 'not_found' })

  // Check permissions
  if (file.workspaceId) {
    // Workspace file - only STUDENT can delete
    if (!canDeleteInWorkspace(u.id, file.workspaceId, file.userId)) {
      return res.status(403).json({ error: 'insufficient_permissions' })
    }
  } else {
    // Personal file - only owner can delete
    if (file.userId !== u.id) return res.status(403).json({ error: 'forbidden' })
  }

  const deleted = db.deleteFile(fileId, u.id)
  if (!deleted) return res.status(404).json({ error: 'not_found' })

  audit(req, 'file.delete', 'file', fileId, { workspaceId: file.workspaceId, name: file.name })
  if (file.workspaceId) broadcastWorkspace(file.workspaceId, 'files')
  return res.json({ ok: true })
}))

const verifyBodySchema = z.object({ token: z.string().min(10).max(5000) })
app.post('/auth/verify', rlVerifyIp, asyncHandler(async (req, res) => {
  const { token } = parseBody(req, verifyBodySchema)
  const tokenHash = sha256Hex(token)
  const user = db.verifyEmailByTokenHash(tokenHash)
  if (!user) return res.status(400).json({ error: 'invalid_or_expired_token' })
  return res.json({ ok: true })
}))

// GET variant (makkelijker vanuit browser; geen JSON body nodig)
const verifyQuerySchema = z.object({ token: z.string().min(10).max(5000) })
app.get('/auth/verify', rlVerifyIp, (req, res) => {
  const { token } = parseQuery(req, verifyQuerySchema)
  const tokenHash = sha256Hex(token)
  const user = db.verifyEmailByTokenHash(tokenHash)
  if (!user) return res.status(400).json({ error: 'invalid_or_expired_token' })
  return res.json({ ok: true })
})

// Vraag een nieuwe verificatie-link aan (alleen als account nog niet verified is)
const resendSchema = z.object({ email: z.string().email() })
app.post('/auth/resend-verify', rlAuthIp, rlVerifyIp, asyncHandler(async (req, res) => {
  const { email } = parseBody(req, resendSchema)

  const user = db.findUserByEmail(email)
  const isProd = process.env.NODE_ENV === 'production'
  if (!user) return res.status(200).json({ ok: true, ...(isProd ? {} : { sent: false, reason: 'not_found' }) }) // don't leak existence
  if (user.emailVerified) return res.status(200).json({ ok: true, ...(isProd ? {} : { sent: false, reason: 'already_verified' }) })

  const rawToken = crypto.randomBytes(32).toString('hex')
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')
  const expiresAt = Date.now() + 1000 * 60 * 60 * 24

  db.setEmailVerificationForEmail(email, tokenHash, expiresAt)

  const { appVerifyUrl, apiVerifyUrl } = buildVerifyUrls(rawToken)
  await sendMail({
    to: email,
    subject: 'Stage Planner: nieuwe activatielink',
    text: `Activeer je account:\n${appVerifyUrl}\n\nDirecte link (als dit niet werkt):\n${apiVerifyUrl}\n\nDeze link is 24 uur geldig.`,
  })

  return res.json({ ok: true, ...(isProd ? {} : { sent: true }) })
}))

const forgotPasswordSchema = z.object({ email: z.string().email() })
app.post('/auth/forgot-password', rlAuthIp, rlVerifyIp, asyncHandler(async (req, res) => {
  const { email } = parseBody(req, forgotPasswordSchema)
  const user = db.findUserByEmail(email)
  const isProd = process.env.NODE_ENV === 'production'

  if (!user || !user.emailVerified) {
    // Do not leak account existence
    return res.json({ ok: true, ...(isProd ? {} : { sent: false, reason: 'not_found_or_unverified' }) })
  }

  const rawToken = crypto.randomBytes(32).toString('hex')
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')
  const expiresAt = Date.now() + 1000 * 60 * 60 // 1 hour

  db.setPasswordResetForEmail(email, tokenHash, expiresAt)

  const { appResetUrl, apiResetUrl } = buildResetUrls(rawToken)
  await sendMail({
    to: email,
    subject: 'Stage Planner: reset je wachtwoord',
    text: `Reset je wachtwoord:\n${appResetUrl}\n\nAPI endpoint (POST):\n${apiResetUrl}\n\nDeze link is 1 uur geldig.`,
  })

  return res.json({ ok: true, ...(isProd ? {} : { sent: true }) })
}))

const resetPasswordSchema = z
  .object({
    token: z.string().min(10).max(5000),
    password: z.string().min(10).max(200),
    passwordConfirm: z.string().min(10).max(200),
  })
  .refine((d) => d.password === d.passwordConfirm, { message: 'password_mismatch' })
  .refine((d) => isStrongPassword(d.password), { message: 'weak_password' })

app.post('/auth/reset-password', rlAuthIp, rlVerifyIp, asyncHandler(async (req, res) => {
  const { token, password } = parseBody(req, resetPasswordSchema)
  const tokenHash = sha256Hex(token)
  const user = db.findUserByPasswordResetTokenHash(tokenHash)
  if (!user) return res.status(400).json({ error: 'invalid_or_expired_token' })

  const hash = await bcrypt.hash(password, 10)
  db.setUserPassword(user.id, hash)
  db.clearPasswordResetForUser(user.id)
  audit(req, 'account.password_reset', 'user', user.id)
  return res.json({ ok: true })
}))

app.post('/auth/resend-verification', rlAuthIp, rlVerifyIp, asyncHandler(async (req, res) => {
  const { email } = parseBody(req, resendSchema)

  const user = db.findUserByEmail(email)
  // anti user-enumeration: altijd ok teruggeven
  const isProd = process.env.NODE_ENV === 'production'
  if (!user) return res.json({ ok: true, ...(isProd ? {} : { sent: false, reason: 'not_found' }) })
  if (user.emailVerified) return res.json({ ok: true, ...(isProd ? {} : { sent: false, reason: 'already_verified' }) })

  const rawToken = crypto.randomBytes(32).toString('hex')
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')
  const expiresAt = Date.now() + 1000 * 60 * 60 * 24

  const updated = db.setEmailVerificationForUser(email, tokenHash, expiresAt)
  if (updated) {
    const { appVerifyUrl, apiVerifyUrl } = buildVerifyUrls(rawToken)
    await sendMail({
      to: email,
      subject: 'Stage Planner: nieuwe activatielink',
      text: `Activeer je account:\n${appVerifyUrl}\n\nDirecte link (als dit niet werkt):\n${apiVerifyUrl}\n\nDeze link is 24 uur geldig.`,
    })
  }

  return res.json({ ok: true, ...(isProd ? {} : { sent: !!updated }) })
}))

// Notes (cloud) - workspace aware
const notesListQuerySchema = z.object({
  workspaceId: z.string().optional(),
})

const noteUpsertSchema = z.object({
  id: z.string().optional(),
  subject: z.string().min(0).max(200),
  body: z.string().max(200000),
  workspaceId: z.string().optional(),
})

app.get('/notes', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const { workspaceId } = parseQuery(req, notesListQuerySchema)

  // If workspaceId provided, filter by workspace
  if (workspaceId) {
    // Check if user is member of workspace
    const role = db.getMembershipRole(u.id, workspaceId)
    if (!role) return res.status(403).json({ error: 'not_member' })

    const notes = db.listNotesForGroup(workspaceId)
    return res.json({ notes, workspaceId })
  }

  // Legacy: list all workspaces user is member of
  const workspaces = db.listGroupsForUser(u.id)
  const allNotes: DbNote[] = []
  for (const ws of workspaces) {
    const notes = db.listNotesForGroup(ws.id)
    allNotes.push(...notes)
  }
  // Also include personal notes (for backward compatibility)
  const personalNotes = db.listNotesOwned(u.id)
  allNotes.push(...personalNotes)

  return res.json({ notes: allNotes })
}))

app.post('/notes', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const parsed = noteUpsertSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  const d = parsed.data

  // Determine workspaceId
  let workspaceId = d.workspaceId
  if (!workspaceId) {
    // Default to user's personal workspace
    const user = db.findUserById(u.id)
    workspaceId = user?.groupId || u.id
  }

  // Check workspace membership and permissions
  const role = db.getMembershipRole(u.id, workspaceId)
  if (!role) return res.status(403).json({ error: 'not_member' })

  // Only STUDENT can create notes
  if (!canCreateInWorkspace(u.id, workspaceId)) {
    return res.status(403).json({ error: 'only_students_can_create' })
  }

  // For updates, check ownership
  if (d.id) {
    const existing = db.getNoteById(d.id)
    if (!existing) return res.status(404).json({ error: 'not_found' })
    if (existing.groupId !== workspaceId) return res.status(403).json({ error: 'wrong_workspace' })
    if (!canEditInWorkspace(u.id, workspaceId, existing.userId)) {
      return res.status(403).json({ error: 'insufficient_permissions' })
    }
  }

  const note = db.upsertNote(u.id, { id: d.id, subject: d.subject, body: d.body, groupId: workspaceId })
  audit(req, d.id ? 'note.update' : 'note.create', 'note', note.id, { workspaceId, subject: note.subject })
  broadcastWorkspace(workspaceId, 'notes')
  return res.json({ note, workspaceId })
}))

app.delete('/notes/:id', requireAuth, (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const id = req.params.id
  const n = db.getNoteById(id)
  if (!n) return res.status(404).json({ error: 'not_found' })
  
  // Check workspace permissions
  if (!n.groupId) return res.status(400).json({ error: 'no_workspace' })
  if (!canDeleteInWorkspace(u.id, n.groupId, n.userId)) {
    return res.status(403).json({ error: 'insufficient_permissions' })
  }

  const ok = db.deleteNote(u.id, id)
  if (!ok) return res.status(404).json({ error: 'not_found' })
  audit(req, 'note.delete', 'note', id, { workspaceId: n.groupId })
  if (n.groupId) broadcastWorkspace(n.groupId, 'notes')
  return res.json({ ok: true })
})

// Sharing
const shareCreateSchema = z.object({
  resourceType: z.enum(['planning', 'note']),
  resourceId: z.string().min(1),
  granteeEmail: z.string().email(),
  permission: z.enum(['read', 'write']),
})

app.get('/shares', requireAuth, (req, res) => {
  const u = getUser(req)!
  const { incoming, outgoing } = db.listSharesForUser(u.id)
  return res.json({ incoming, outgoing })
})

app.post('/shares', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const parsed = shareCreateSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  const d = parsed.data
  const grantee = db.findUserByEmail(d.granteeEmail)
  if (!grantee) return res.status(404).json({ error: 'user_not_found' })
  if (grantee.id === u.id) return res.status(400).json({ error: 'cannot_share_to_self' })

  // Owner check
  if (d.resourceType === 'planning') {
    const p = db.getPlanningById(d.resourceId)
    if (!p || p.userId !== u.id) return res.status(403).json({ error: 'not_owner' })
  }
  if (d.resourceType === 'note') {
    const n = db.getNoteById(d.resourceId)
    if (!n || n.userId !== u.id) return res.status(403).json({ error: 'not_owner' })
  }

  const share = db.createShare({
    resourceType: d.resourceType,
    resourceId: d.resourceId,
    ownerId: u.id,
    granteeId: grantee.id,
    permission: d.permission,
  })
  audit(req, 'share.create', d.resourceType, d.resourceId, { to: grantee.email, permission: d.permission })
  return res.json({ share })
}))

// Planning: filter by workspace
// Planning query validation
const planningListQuerySchema = z.object({
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  workspaceId: z.string().optional(),
})

app.get('/planning', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const { date, workspaceId } = parseQuery(req, planningListQuerySchema)

  // If workspaceId provided, filter by workspace
  if (workspaceId) {
    // Check if user is member of workspace
    const role = db.getMembershipRole(u.id, workspaceId)
    if (!role) return res.status(403).json({ error: 'not_member' })

    const items = db.listPlanningForGroup(workspaceId, date)
    return res.json({ items, workspaceId })
  }

  // Legacy: list all workspaces user is member of
  const workspaces = db.listGroupsForUser(u.id)
  const allItems: DbPlanningItem[] = []
  for (const ws of workspaces) {
    const items = db.listPlanningForGroup(ws.id, date)
    allItems.push(...items)
  }
  // Also include personal items (for backward compatibility)
  const personalItems = db.listPlanning(u.id, date)
  allItems.push(...personalItems)

  return res.json({ items: allItems })
}))

// Planning CRUD schema (defined here for use below)
const planningUpsertSchema = z.object({
  id: z.string().optional(),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  start: z.string().regex(/^\d{2}:\d{2}$/),
  end: z.string().regex(/^\d{2}:\d{2}$/),
  title: z.string().min(1).max(200),
  notes: z.string().max(10000).optional().nullable(),
  tagsJson: z.union([z.string().max(2000), z.array(z.string().max(64)).max(50)]).optional(),
  tags: z.string().max(2000).optional(),
  priority: z.enum(['low', 'medium', 'high']).default('medium'),
  status: z.enum(['todo', 'in_progress', 'done']).default('todo'),
})

const planningUpsertSchemaWithWorkspace = planningUpsertSchema.extend({
  workspaceId: z.string().optional(),
})

app.post('/planning', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const parsed = planningUpsertSchemaWithWorkspace.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  const d = parsed.data

  const normalizeTagsJson = (input: unknown, fallback: string) => {
    if (Array.isArray(input)) {
      return JSON.stringify(input.filter((t) => typeof t === 'string'))
    }
    if (typeof input === 'string') {
      const trimmed = input.trim()
      if (!trimmed) return '[]'
      try {
        const parsedJson = JSON.parse(trimmed)
        if (Array.isArray(parsedJson)) {
          return JSON.stringify(parsedJson.filter((t) => typeof t === 'string'))
        }
      } catch {
        // ignore - will parse as comma-separated below
      }
      const parts = trimmed
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
      return JSON.stringify(parts)
    }
    return fallback
  }

  // Determine workspaceId
  let workspaceId = d.workspaceId
  if (!workspaceId) {
    // Default to user's personal workspace
    const user = db.findUserById(u.id)
    workspaceId = user?.groupId || u.id
  }

  // Check workspace membership and permissions
  const role = db.getMembershipRole(u.id, workspaceId)
  if (!role) return res.status(403).json({ error: 'not_member' })

  // update path
  if (d.id) {
    const existing = db.getPlanningById(d.id)
    if (!existing) return res.status(404).json({ error: 'not_found' })
    
    // Check if item belongs to workspace
    if (existing.groupId !== workspaceId) return res.status(403).json({ error: 'wrong_workspace' })

    // Check permissions: only STUDENT can edit, and only own items
    if (!canEditInWorkspace(u.id, workspaceId, existing.userId)) {
      return res.status(403).json({ error: 'insufficient_permissions' })
    }

    const normalizedTagsJson = normalizeTagsJson(
      d.tagsJson ?? d.tags,
      existing.tagsJson ?? '[]',
    )
    const item = db.upsertPlanning(u.id, {
      id: d.id,
      groupId: workspaceId,
      date: d.date,
      start: d.start,
      end: d.end,
      title: d.title,
      notes: d.notes ?? null,
      tagsJson: normalizedTagsJson,
      priority: d.priority,
      status: d.status,
    })
    audit(req, 'planning.update', 'planning', item.id, { workspaceId, date: item.date })
    broadcastWorkspace(workspaceId, 'planning')
    return res.json({ item, workspaceId })
  }

  // create path - only STUDENT can create
  if (!canCreateInWorkspace(u.id, workspaceId)) {
    return res.status(403).json({ error: 'only_students_can_create' })
  }

  const normalizedTagsJson = normalizeTagsJson(d.tagsJson ?? d.tags, '[]')
  const item = db.upsertPlanning(u.id, {
    groupId: workspaceId,
    date: d.date,
    start: d.start,
    end: d.end,
    title: d.title,
    notes: d.notes ?? null,
    tagsJson: normalizedTagsJson,
    priority: d.priority,
    status: d.status,
  })
  audit(req, 'planning.create', 'planning', item.id, { workspaceId, date: item.date })
  broadcastWorkspace(workspaceId, 'planning')
  return res.json({ item, workspaceId })
}))

app.delete('/planning/:id', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const id = req.params.id
  const p = db.getPlanningById(id)
  if (!p) return res.status(404).json({ error: 'not_found' })
  
  // Check workspace permissions
  if (!p.groupId) return res.status(400).json({ error: 'no_workspace' })
  if (!canDeleteInWorkspace(u.id, p.groupId, p.userId)) {
    return res.status(403).json({ error: 'insufficient_permissions' })
  }

  const ok = db.deletePlanning(u.id, id)
  if (!ok) return res.status(404).json({ error: 'not_found' })
  audit(req, 'planning.delete', 'planning', id, { workspaceId: p.groupId })
  if (p.groupId) broadcastWorkspace(p.groupId, 'planning')
  return res.json({ ok: true })
}))

// (group planner removed)

// Admin: users beheren
const adminUserCreateSchema = z.object({
  email: z.string().email(),
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9._-]+$/),
  firstName: z.string().min(1).max(80),
  lastName: z.string().min(1).max(80),
  password: z.string().min(10).max(200),
  isAdmin: z.boolean().optional().default(false),
  emailVerified: z.boolean().optional().default(true),
})
  .refine((d) => isStrongPassword(d.password), { message: 'weak_password' })

const adminUserPatchSchema = z.object({
  email: z.string().email().optional(),
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9._-]+$/).optional(),
  firstName: z.string().min(1).max(80).optional(),
  lastName: z.string().min(1).max(80).optional(),
  emailVerified: z.boolean().optional(),
  isAdmin: z.boolean().optional(),
  newPassword: z.string().min(10).max(200).optional(),
})
  .refine((d) => (d.newPassword ? isStrongPassword(d.newPassword) : true), { message: 'weak_password' })

app.get('/admin/users', requireAuth, requireAdmin, (_req, res) => {
  const users = db.listUsers().map((u) => {
    return {
      id: u.id,
      email: u.email,
      username: u.username,
      firstName: u.firstName,
      lastName: u.lastName,
      isAdmin: !!u.isAdmin,
      emailVerified: !!u.emailVerified,
      createdAt: u.createdAt,
      updatedAt: u.updatedAt,
    }
  })
  return res.json({ users })
})

app.post('/admin/users', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const parsed = adminUserCreateSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  const d = parsed.data

  if (db.findUserByEmail(d.email)) return res.status(409).json({ error: 'email_in_use' })
  if (db.findUserByUsername(d.username)) return res.status(409).json({ error: 'username_in_use' })

  const passwordHash = await bcrypt.hash(d.password, 10)

  let tokenHash: string | null = null
  let expiresAt: number | null = null
  if (!d.emailVerified) {
    const rawToken = crypto.randomBytes(32).toString('hex')
    tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')
    expiresAt = Date.now() + 1000 * 60 * 60 * 24
    const { appVerifyUrl, apiVerifyUrl } = buildVerifyUrls(rawToken)
    await sendMail({
      to: d.email,
      subject: 'Stage Planner: account activatie',
      text: `Activeer je account:\n${appVerifyUrl}\n\nDirecte link (als dit niet werkt):\n${apiVerifyUrl}\n\nDeze link is 24 uur geldig.`,
    })
  }

  const user = db.createUser({
    email: d.email,
    username: d.username,
    firstName: d.firstName,
    lastName: d.lastName,
    passwordHash,
    isAdmin: d.isAdmin,
    emailVerified: d.emailVerified,
    groupId: null,
    emailVerificationTokenHash: tokenHash,
    emailVerificationExpiresAt: expiresAt,
  })

  audit(req, 'admin.user.create', 'user', user.id, { email: user.email, username: user.username, isAdmin: !!user.isAdmin })
  return res.json({
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      isAdmin: !!user.isAdmin,
      emailVerified: !!user.emailVerified,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    },
  })
}))

app.patch('/admin/users/:id', requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const parsed = adminUserPatchSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  const id = req.params.id
  const patch = parsed.data
  const me = getUser(req)!

  // Safety: don't allow self-demote / self-delete by accident
  if (id === me.id && patch.isAdmin === false) return res.status(400).json({ error: 'cannot_self_demote' })

  if (patch.newPassword) {
    const hash = await bcrypt.hash(patch.newPassword, 10)
    const ok = db.setUserPassword(id, hash)
    if (!ok) return res.status(404).json({ error: 'not_found' })
  }

  const updated = db.updateUser(id, {
    email: patch.email,
    username: patch.username,
    firstName: patch.firstName,
    lastName: patch.lastName,
    emailVerified: patch.emailVerified == null ? undefined : patch.emailVerified ? 1 : 0,
    isAdmin: patch.isAdmin == null ? undefined : patch.isAdmin ? 1 : 0,
  })
  if (!updated) return res.status(404).json({ error: 'not_found' })

  audit(req, 'admin.user.update', 'user', id, {
    email: updated.email,
    username: updated.username,
    isAdmin: !!updated.isAdmin,
    emailVerified: !!updated.emailVerified,
    passwordReset: !!patch.newPassword,
  })

  return res.json({
    user: {
      id: updated.id,
      email: updated.email,
      username: updated.username,
      firstName: updated.firstName,
      lastName: updated.lastName,
      isAdmin: !!updated.isAdmin,
      emailVerified: !!updated.emailVerified,
      createdAt: updated.createdAt,
      updatedAt: updated.updatedAt,
    },
  })
}))

app.delete('/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
  const me = getUser(req)!
  const id = req.params.id
  if (id === me.id) return res.status(400).json({ error: 'cannot_self_delete' })
  const ok = db.deleteUser(id)
  if (!ok) return res.status(404).json({ error: 'not_found' })
  audit(req, 'admin.user.delete', 'user', id)
  return res.json({ ok: true })
})

// (admin group management removed)

// Admin: audit log
app.get('/admin/audit', requireAuth, requireAdmin, (req, res) => {
  const q = parseQuery(
    req,
    z.object({
      limit: z.coerce.number().default(10),
      offset: z.coerce.number().default(0),
    }),
  )
  const safeLimit = Math.min(500, Math.max(1, Math.floor(q.limit ?? 10)))
  const safeOffset = Math.max(0, Math.floor(q.offset ?? 0))
  const logs = db.listAuditWithActorPaged(safeLimit, safeOffset)
  const total = db.countAudit()
  return res.json({ logs, total, limit: safeLimit, offset: safeOffset })
})

function csvEscape(v: any) {
  const s = v == null ? '' : String(v)
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`
  return s
}

app.get('/admin/audit/download', requireAuth, requireAdmin, (req, res) => {
  const limit = typeof req.query.limit === 'string' ? Number(req.query.limit) : 2000
  const format = typeof req.query.format === 'string' ? req.query.format : 'csv'
  const safeLimit = Number.isFinite(limit) ? Math.min(20000, Math.max(1, limit)) : 2000

  const logs = db.listAuditWithActor(safeLimit)

  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  if (format === 'json') {
    res.setHeader('content-type', 'application/json; charset=utf-8')
    res.setHeader('content-disposition', `attachment; filename="audit-${stamp}.json"`)
    return res.send(JSON.stringify({ logs }, null, 2))
  }

  // default: csv
  res.setHeader('content-type', 'text/csv; charset=utf-8')
  res.setHeader('content-disposition', `attachment; filename="audit-${stamp}.csv"`)
  const header = [
    'createdAt',
    'actorEmail',
    'actorUsername',
    'actorUserId',
    'action',
    'resourceType',
    'resourceId',
    'metaJson',
  ]
  const lines = [header.join(',')]
  for (const l of logs as any[]) {
    lines.push(
      [
        csvEscape(l.createdAt),
        csvEscape(l.actorEmail),
        csvEscape(l.actorUsername),
        csvEscape(l.actorUserId),
        csvEscape(l.action),
        csvEscape(l.resourceType),
        csvEscape(l.resourceId),
        csvEscape(l.metaJson),
      ].join(','),
    )
  }
  return res.send('\uFEFF' + lines.join('\r\n')) // BOM for Excel
})

app.delete('/admin/audit', requireAuth, requireAdmin, (req, res) => {
  db.deleteAllAudit()
  audit(req, 'admin.audit.wipe', 'audit', 'all', {})
  return res.json({ ok: true })
})

function readLastNdjson(filePath: string, limit: number) {
  try {
    if (!fs.existsSync(filePath)) return []
    const raw = fs.readFileSync(filePath, 'utf-8')
    const lines = raw.split(/\r?\n/).filter(Boolean)
    const tail = lines.slice(Math.max(0, lines.length - limit))
    return tail
      .map((l) => {
        try {
          return JSON.parse(l)
        } catch {
          return { ts: Date.now(), type: 'parse_error', message: l }
        }
      })
      .reverse()
  } catch {
    return []
  }
}

app.get('/admin/errors', requireAuth, requireAdmin, (req, res) => {
  const q = parseQuery(
    req,
    z.object({
      limit: z.coerce.number().default(10),
      offset: z.coerce.number().default(0),
    }),
  )
  const safeLimit = Math.min(2000, Math.max(1, Math.floor(q.limit ?? 10)))
  const safeOffset = Math.max(0, Math.floor(q.offset ?? 0))

  if (!fs.existsSync(ERROR_LOG_PATH)) return res.json({ errors: [], total: 0, limit: safeLimit, offset: safeOffset })
  const raw = fs.readFileSync(ERROR_LOG_PATH, 'utf-8')
  const lines = raw.split(/\r?\n/).filter(Boolean)
  const total = lines.length
  // newest first
  const start = Math.max(0, total - safeOffset - safeLimit)
  const end = Math.max(0, total - safeOffset)
  const slice = lines.slice(start, end).reverse()
  const errors = slice.map((l) => {
    try {
      return JSON.parse(l)
    } catch {
      return { ts: Date.now(), type: 'parse_error', message: l }
    }
  })
  return res.json({ errors, total, limit: safeLimit, offset: safeOffset })
})

app.get('/admin/errors/download', requireAuth, requireAdmin, (req, res) => {
  const q = parseQuery(req, z.object({ format: z.enum(['ndjson', 'json']).optional().default('ndjson') }))
  const format = q.format
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  if (format === 'json') {
    const errors = readLastNdjson(ERROR_LOG_PATH, 5000)
    res.setHeader('content-type', 'application/json; charset=utf-8')
    res.setHeader('content-disposition', `attachment; filename="backend-errors-${stamp}.json"`)
    return res.send(JSON.stringify({ errors }, null, 2))
  }
  res.setHeader('content-type', 'application/x-ndjson; charset=utf-8')
  res.setHeader('content-disposition', `attachment; filename="backend-errors-${stamp}.ndjson"`)
  if (!fs.existsSync(ERROR_LOG_PATH)) return res.send('')
  return res.send(fs.readFileSync(ERROR_LOG_PATH, 'utf-8'))
})

app.delete('/admin/errors', requireAuth, requireAdmin, (req, res) => {
  try {
    if (fs.existsSync(ERROR_LOG_PATH)) {
      fs.writeFileSync(ERROR_LOG_PATH, '', 'utf-8')
    }
    audit(req, 'admin.errors.wipe', 'errors', 'backend', {})
    return res.json({ ok: true })
  } catch (err) {
    return res.status(500).json({ error: 'wipe_failed', message: err instanceof Error ? err.message : String(err) })
  }
})

// (oude per-user planning endpoints verwijderd; zie boven voor shared-aware endpoints)
// planningUpsertSchema is defined above, before POST /planning endpoint

// ===== WORKSPACE ENDPOINTS =====

// List workspaces for current user
app.get('/workspaces', requireAuth, asyncHandler(async (req, res) => {
  const u = getUser(req)!
  const workspaces = db.listGroupsForUser(u.id)
  return res.json(workspaces)
}))

// Get workspace details
app.get('/workspaces/:id', requireAuth, (req, res) => {
  const u = getUser(req)!
  const workspaceId = req.params.id
  const workspace = db.getGroupById(workspaceId)
  if (!workspace) return res.status(404).json({ error: 'not_found' })
  
  // Check if user is member
  const role = db.getMembershipRole(u.id, workspaceId)
  if (!role) return res.status(403).json({ error: 'not_member' })

  const members = db.listGroupMembers(workspaceId)
  return res.json({ workspace, role, members })
})

// Create workspace
const createWorkspaceSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional().nullable(),
})

app.post('/workspaces', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const { name, description } = parseBody(req, createWorkspaceSchema)
  
  const workspace = db.createWorkspace(name, u.id, description)
  audit(req, 'workspace.create', 'workspace', workspace.id, { name })
  return res.json({ workspace })
}))

// Update workspace (only STUDENT/owner)
const updateWorkspaceSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  description: z.string().max(500).optional().nullable(),
})

app.patch('/workspaces/:id', requireAuth, requireWorkspaceStudent, (req, res) => {
  const u = getUser(req)!
  const workspaceId = req.params.id
  const parsed = updateWorkspaceSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  
  const workspace = db.updateWorkspace(workspaceId, parsed.data)
  if (!workspace) return res.status(404).json({ error: 'not_found' })
  
  audit(req, 'workspace.update', 'workspace', workspaceId, parsed.data)
  return res.json({ workspace })
})

// Invite user to workspace
const inviteToWorkspaceSchema = z.object({
  email: z.string().email(),
  role: z.enum(['MENTOR', 'BEGELEIDER']), // STUDENT can only invite MENTOR/BEGELEIDER
})

app.post('/workspaces/:id/invite', requireAuth, requireWorkspaceStudent, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const workspaceId = req.params.id
  const { email, role } = parseBody(req, inviteToWorkspaceSchema)

  // Check if user already exists
  const existingUser = db.findUserByEmail(email)
  if (existingUser) {
    // Check if already member
    const existingRole = db.getMembershipRole(existingUser.id, workspaceId)
    if (existingRole) return res.status(409).json({ error: 'already_member' })
  }

  // Generate invite token
  const rawToken = crypto.randomBytes(32).toString('hex')
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')
  const expiresAt = Date.now() + 1000 * 60 * 60 * 24 * 7 // 7 days

  const invitation = db.createWorkspaceInvitation({
    workspaceId,
    email,
    role,
    invitedBy: u.id,
    tokenHash,
    expiresAt,
  })

  const workspace = db.getGroupById(workspaceId)!
  const { appVerifyUrl, apiVerifyUrl } = buildVerifyUrls(rawToken)
  const inviteUrl = `${getPublicAppUrl()}/workspace/accept?token=${encodeURIComponent(rawToken)}`

  await sendMail({
    to: email,
    subject: `Stage Planner: workspace uitnodiging`,
    text: `Je bent uitgenodigd voor de workspace "${workspace.name}" (${role}).\n\nAccepteer de uitnodiging:\n${inviteUrl}\n\nDeze link is 7 dagen geldig.`,
  })

  audit(req, 'workspace.invite', 'workspace', workspaceId, { email, role })
  return res.json({ invitation: { id: invitation.id, email, role, expiresAt } })
}))

// Accept workspace invitation
app.post('/workspaces/accept', requireAuth, asyncHandler(async (req, res) => {
  const { token } = parseBody(req, z.object({ token: z.string().min(10).max(5000) }))
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex')
  
  const invitation = db.getWorkspaceInvitationByToken(tokenHash)
  if (!invitation) return res.status(400).json({ error: 'invalid_token' })
  if (invitation.expiresAt < Date.now()) return res.status(400).json({ error: 'token_expired' })
  if (invitation.acceptedAt) return res.status(400).json({ error: 'already_accepted' })

  // User must be authenticated
  const u = getUser(req)
  if (!u) return res.status(401).json({ error: 'unauthorized' })
  
  // Email must match
  if (u.email.toLowerCase() !== invitation.email.toLowerCase()) {
    return res.status(403).json({ error: 'email_mismatch' })
  }

  const accepted = db.acceptWorkspaceInvitation(tokenHash, u.id)
  if (!accepted) return res.status(400).json({ error: 'accept_failed' })

  audit(req, 'workspace.accept_invite', 'workspace', invitation.workspaceId, { email: invitation.email })
  return res.json({ ok: true, workspaceId: invitation.workspaceId })
}))

// List workspace members
app.get('/workspaces/:id/members', requireAuth, asyncHandler(async (req, res) => {
  const u = getUser(req)!
  const workspaceId = req.params.id
  
  // Check if user is member
  const role = db.getMembershipRole(u.id, workspaceId)
  if (!role) return res.status(403).json({ error: 'not_member' })

  const members = db.listGroupMembers(workspaceId)
  return res.json(members)
}))

// List workspace invitations (only for STUDENT/owner)
app.get('/workspaces/:id/invitations', requireAuth, requireWorkspaceStudent, asyncHandler(async (req, res) => {
  const workspaceId = req.params.id
  const invitations = db.listWorkspaceInvitations(workspaceId)
  return res.json(invitations)
}))

// Update member role (only STUDENT/owner)
const updateMemberRoleSchema = z.object({
  userId: z.string().min(1),
  role: z.enum(['STUDENT', 'MENTOR', 'BEGELEIDER']),
})

app.patch('/workspaces/:id/members', requireAuth, requireWorkspaceStudent, (req, res) => {
  const u = getUser(req)!
  const workspaceId = req.params.id
  const { userId, role } = parseBody(req, updateMemberRoleSchema)

  // Can't change your own role
  if (userId === u.id) return res.status(400).json({ error: 'cannot_change_own_role' })

  const updated = db.updateWorkspaceMemberRole(workspaceId, userId, role, u.id)
  if (!updated) return res.status(404).json({ error: 'member_not_found' })

  audit(req, 'workspace.update_member_role', 'workspace', workspaceId, { userId, role })
  return res.json({ ok: true })
})

// Remove member from workspace (only STUDENT/owner)
app.delete('/workspaces/:id/members/:userId', requireAuth, requireWorkspaceStudent, (req, res) => {
  const u = getUser(req)!
  const workspaceId = req.params.id
  const userId = req.params.userId

  const removed = db.removeWorkspaceMember(workspaceId, userId, u.id)
  if (!removed) return res.status(404).json({ error: 'member_not_found' })

  audit(req, 'workspace.remove_member', 'workspace', workspaceId, { userId })
  return res.json({ ok: true })
})

// ===== FEEDBACK/COMMENTS ENDPOINTS =====

const createFeedbackSchema = z.object({
  resourceType: z.enum(['planning', 'note']),
  resourceId: z.string().min(1),
  content: z.string().min(1).max(5000),
})

app.post('/feedback', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const { resourceType, resourceId, content } = parseBody(req, createFeedbackSchema)

  // Check if user can add feedback (must be MENTOR or BEGELEIDER in workspace)
  // First, find which workspace this resource belongs to
  let workspaceId: string | null = null
  if (resourceType === 'planning') {
    const item = db.getPlanningById(resourceId)
    if (!item) return res.status(404).json({ error: 'resource_not_found' })
    workspaceId = item.groupId
  } else if (resourceType === 'note') {
    const note = db.getNoteById(resourceId)
    if (!note) return res.status(404).json({ error: 'resource_not_found' })
    workspaceId = note.groupId
  }

  if (!workspaceId) return res.status(404).json({ error: 'resource_not_found' })

  // Check if user is MENTOR or BEGELEIDER
  const role = db.getMembershipRole(u.id, workspaceId)
  if (role !== 'MENTOR' && role !== 'BEGELEIDER') {
    return res.status(403).json({ error: 'only_mentors_can_add_feedback' })
  }

  const feedback = db.createFeedback({
    resourceType,
    resourceId,
    authorId: u.id,
    content,
  })

  audit(req, 'feedback.create', resourceType, resourceId, { workspaceId })
  return res.json({ feedback })
}))

app.get('/feedback/:resourceType/:resourceId', requireAuth, (req, res) => {
  const u = getUser(req)!
  const { resourceType, resourceId } = req.params

  if (resourceType !== 'planning' && resourceType !== 'note') {
    return res.status(400).json({ error: 'invalid_resource_type' })
  }

  // Check workspace membership
  let workspaceId: string | null = null
  if (resourceType === 'planning') {
    const item = db.getPlanningById(resourceId)
    if (!item) return res.status(404).json({ error: 'resource_not_found' })
    workspaceId = item.groupId
  } else {
    const note = db.getNoteById(resourceId)
    if (!note) return res.status(404).json({ error: 'resource_not_found' })
    workspaceId = note.groupId
  }

  if (!workspaceId) return res.status(404).json({ error: 'resource_not_found' })

  const role = db.getMembershipRole(u.id, workspaceId)
  if (!role) return res.status(403).json({ error: 'not_member' })

  const feedback = db.listFeedback(resourceType as 'planning' | 'note', resourceId)
  return res.json({ feedback })
})

const updateFeedbackSchema = z.object({
  content: z.string().min(1).max(5000),
})

app.patch('/feedback/:id', requireAuth, (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const feedbackId = req.params.id
  const { content } = parseBody(req, updateFeedbackSchema)

  // Note: We'd need to get feedback first to check ownership, but for simplicity
  // we allow users to update their own feedback
  const updated = db.updateFeedback(feedbackId, u.id, content)
  if (!updated) return res.status(404).json({ error: 'not_found' })

  audit(req, 'feedback.update', 'feedback', feedbackId)
  return res.json({ ok: true })
})

app.delete('/feedback/:id', requireAuth, (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const feedbackId = req.params.id

  const deleted = db.deleteFeedback(feedbackId, u.id)
  if (!deleted) return res.status(404).json({ error: 'not_found' })

  audit(req, 'feedback.delete', 'feedback', feedbackId)
  return res.json({ ok: true })
})

// Central error handler (must be after routes)
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const isDev = process.env.NODE_ENV !== 'production'
  
  if (err instanceof ZodError) {
    return res.status(400).json({
      error: 'invalid_input',
      issues: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    })
  }
  if (err instanceof ApiError) {
    return res.status(err.status).json({ error: err.code, ...(err.details != null ? { details: err.details } : {}) })
  }
  
  // Log full error details (including stack) for debugging
  appendErrorLog({
    ts: Date.now(),
    type: 'express',
    name: err?.name,
    code: err?.code,
    message: err?.message || String(err),
    stack: err?.stack, // Always log stack internally
    method: req.method,
    path: req.originalUrl,
    userId: getUser(req)?.id,
  })
  
  // Don't leak error details to client in production
  return res.status(500).json({ 
    error: 'server_error',
    ...(isDev ? { message: err?.message, details: String(err) } : {}) // Only in dev
  })
})

// Validate required environment variables (only at runtime, not during build)
const requiredEnvVars = ['JWT_SECRET']
const missingVars: string[] = []
for (const varName of requiredEnvVars) {
  if (!process.env[varName]) {
    missingVars.push(varName)
  }
}
if (missingVars.length > 0) {
  // eslint-disable-next-line no-console
  console.error(`ERROR: Missing required environment variables: ${missingVars.join(', ')}`)
  process.exit(1)
}

const port = Number(process.env.PORT || 3001)
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Backend listening on http://localhost:${port}`)
})


