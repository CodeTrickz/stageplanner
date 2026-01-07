import cors from 'cors'
import dotenv from 'dotenv'
import express from 'express'
import helmet from 'helmet'
import morgan from 'morgan'
import bcrypt from 'bcryptjs'
import { ZodError, z } from 'zod'
import { getUser, requireAuth, signAccessToken } from './auth'
import { db } from './db'
import path from 'node:path'
import crypto from 'node:crypto'
import { sendMail } from './mail'
import fs from 'node:fs'

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

// Load env from backend/env.local if it exists (no dotfile needed)
dotenv.config({ path: path.resolve(__dirname, '..', 'env.local') })

const app = express()
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

app.get('/health', (_req, res) => res.json({ ok: true }))

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

  const existing = db.findUserByEmail(email)
  if (existing) return

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
  key: (req) => `${req.ip || 'unknown'}:${String((req.body as any)?.email || '').trim().toLowerCase()}`,
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
    subject: 'Activeer je account (Stage Planner)',
    text: `Welkom ${user.firstName}!\n\nKlik om je account te activeren:\n${appVerifyUrl}\n\nWerkt dat niet? Gebruik deze directe link:\n${apiVerifyUrl}\n\nDeze link is 24 uur geldig.`,
  })

  return res.json({ ok: true, message: 'verification_required' })
}))

const loginSchema = z.object({
  email: z.string().email(),
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
  const { email, password } = parseBody(req, loginSchema)
  const user = db.findUserByEmail(email)
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
    subject: 'Nieuwe activatie-link (Stage Planner)',
    text: `Klik om je account te activeren:\n${appVerifyUrl}\n\nWerkt dat niet? Directe link:\n${apiVerifyUrl}\n\nDeze link is 24 uur geldig.`,
  })

  return res.json({ ok: true, ...(isProd ? {} : { sent: true }) })
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
      subject: 'Nieuwe activatie-link (Stage Planner)',
      text: `Klik om je account te activeren:\n${appVerifyUrl}\n\nWerkt dat niet? Directe link:\n${apiVerifyUrl}\n\nDeze link is 24 uur geldig.`,
    })
  }

  return res.json({ ok: true, ...(isProd ? {} : { sent: !!updated }) })
}))

// Notes query validation
const notesListQuerySchema = z.object({
  scope: z.enum(['all', 'owned', 'shared']).optional().default('all'),
})

// Notes (cloud)
const noteUpsertSchema = z.object({
  id: z.string().optional(),
  subject: z.string().min(0).max(200),
  body: z.string().max(200000),
})

app.get('/notes', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const { scope } = parseQuery(req, notesListQuerySchema)
  const owned = scope === 'shared' ? [] : db.listNotesOwned(u.id)
  const shared = scope === 'owned' ? [] : db.listNotesSharedForUser(u.id)
  return res.json({ owned, shared })
}))

app.post('/notes', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const parsed = noteUpsertSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  const d = parsed.data
  const note = db.upsertNote(u.id, { id: d.id, subject: d.subject, body: d.body, groupId: u.id })
  audit(req, d.id ? 'note.update' : 'note.create', 'note', note.id, { subject: note.subject })
  return res.json({ note })
}))

app.delete('/notes/:id', requireAuth, (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const id = req.params.id
  const n = db.getNoteById(id)
  if (!n) return res.status(404).json({ error: 'not_found' })
  if (n.userId !== u.id) return res.status(403).json({ error: 'not_owner' })
  const ok = db.deleteNote(u.id, id)
  if (!ok) return res.status(404).json({ error: 'not_found' })
  audit(req, 'note.delete', 'note', id)
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

// Planning: include shared items (scope=owned|shared|all)
// Planning query validation
const planningListQuerySchema = z.object({
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  scope: z.enum(['all', 'owned', 'shared']).optional().default('all'),
})

app.get('/planning', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const { date, scope } = parseQuery(req, planningListQuerySchema)

  const owned = scope === 'shared' ? [] : db.listPlanning(u.id, date)
  const sharedAll = scope === 'owned' ? [] : db.listPlanningSharedForUser(u.id)
  const shared = date ? sharedAll.filter((p) => p.date === date) : sharedAll

  return res.json({ owned, shared })
}))

app.post('/planning', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const parsed = planningUpsertSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'invalid_input' })
  const d = parsed.data

  // update path
  if (d.id) {
    const owned = db.getPlanningById(d.id)
    if (owned && owned.userId === u.id) {
      const item = db.upsertPlanning(u.id, {
        id: d.id,
        groupId: u.id,
        date: d.date,
        start: d.start,
        end: d.end,
        title: d.title,
        notes: d.notes ?? null,
        tagsJson: d.tagsJson ?? owned.tagsJson ?? '[]',
        priority: d.priority,
        status: d.status,
      })
      audit(req, 'planning.update', 'planning', item.id, { date: item.date })
      return res.json({ item, scope: 'owned' })
    }

    const sh = db.findSharePermission('planning', d.id, u.id)
    if (!sh) return res.status(404).json({ error: 'not_found' })
    if (sh.permission !== 'write') return res.status(403).json({ error: 'read_only' })

    const sharedItem = db.getPlanningById(d.id)
    if (!sharedItem) return res.status(404).json({ error: 'not_found' })

    const item = db.upsertPlanning(sh.ownerId, {
      id: d.id,
      groupId: sh.ownerId,
      date: d.date,
      start: d.start,
      end: d.end,
      title: d.title,
      notes: d.notes ?? null,
      tagsJson: d.tagsJson ?? sharedItem.tagsJson ?? '[]',
      priority: d.priority,
      status: d.status,
    })
    audit(req, 'planning.update', 'planning', item.id, { shared: true, date: item.date })
    return res.json({ item, scope: 'shared' })
  }

  // create path (owned)
  const item = db.upsertPlanning(u.id, {
    groupId: u.id,
    date: d.date,
    start: d.start,
    end: d.end,
    title: d.title,
    notes: d.notes ?? null,
    tagsJson: d.tagsJson ?? '[]',
    priority: d.priority,
    status: d.status,
  })
  audit(req, 'planning.create', 'planning', item.id, { date: item.date })
  return res.json({ item, scope: 'owned' })
}))

app.delete('/planning/:id', requireAuth, asyncHandler(async (req, res) => {
  const u = getDbUserOr401(req, res)
  if (!u) return
  const id = req.params.id
  const p = db.getPlanningById(id)
  if (!p) return res.status(404).json({ error: 'not_found' })
  if (p.userId !== u.id) return res.status(403).json({ error: 'not_owner' })
  const ok = db.deletePlanning(u.id, id)
  if (!ok) return res.status(404).json({ error: 'not_found' })
  audit(req, 'planning.delete', 'planning', id)
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
      subject: 'Activeer je account (Stage Planner)',
      text: `Welkom ${d.firstName}!\n\nKlik om je account te activeren:\n${appVerifyUrl}\n\nWerkt dat niet? Directe link:\n${apiVerifyUrl}\n\nDeze link is 24 uur geldig.`,
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

// Planning CRUD (per user)
const planningUpsertSchema = z.object({
  id: z.string().optional(),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  start: z.string().regex(/^\d{2}:\d{2}$/),
  end: z.string().regex(/^\d{2}:\d{2}$/),
  title: z.string().min(1).max(200),
  notes: z.string().max(10000).optional().nullable(),
  tagsJson: z.string().max(2000).optional(),
  priority: z.enum(['low', 'medium', 'high']).default('medium'),
  status: z.enum(['todo', 'in_progress', 'done']).default('todo'),
})

// (oude per-user planning endpoints verwijderd; zie boven voor shared-aware endpoints)

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


