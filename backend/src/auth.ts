import type { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import type { SignOptions } from 'jsonwebtoken'

export type JwtPayload = { sub: string; email: string; isAdmin: boolean }

export function getJwtSecret() {
  const secret = process.env.JWT_SECRET
  if (!secret) throw new Error('Missing JWT_SECRET')
  return secret
}

export function signAccessToken(payload: JwtPayload) {
  // Keep sessions short by default. Can be overridden, e.g. "2h", "8h", "1d"
  const expiresInRaw = process.env.JWT_EXPIRES_IN || '8h'
  const expiresIn = expiresInRaw as SignOptions['expiresIn']
  return jwt.sign(payload, getJwtSecret(), { expiresIn })
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header('authorization') || ''
  const [kind, token] = header.split(' ')
  if (kind !== 'Bearer' || !token) return res.status(401).json({ error: 'unauthorized' })

  try {
    const decoded = jwt.verify(token, getJwtSecret()) as JwtPayload
    ;(req as any).user = { id: decoded.sub, email: decoded.email, isAdmin: !!decoded.isAdmin }
    return next()
  } catch {
    return res.status(401).json({ error: 'unauthorized' })
  }
}

export function getUser(req: Request) {
  return (req as any).user as { id: string; email: string; isAdmin: boolean } | undefined
}


