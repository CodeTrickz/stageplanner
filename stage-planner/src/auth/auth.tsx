import React, { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { db } from '../db/db'

type User = {
  id: string
  email: string
  username?: string
  firstName?: string
  lastName?: string
  isAdmin?: boolean
  emailVerified?: boolean
}
type AuthState = { token: string; user: User; expiresAt: number }

type AuthContextValue = {
  token: string | null
  user: User | null
  login: (token: string, user: User) => void
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

const LS_KEY = 'stageplanner.auth'

function decodeJwtPayload(token: string): any | null {
  try {
    const parts = token.split('.')
    if (parts.length < 2) return null
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
    const json = atob(padded)
    return JSON.parse(json)
  } catch {
    return null
  }
}

function enrichUserFromToken(token: string, user: User): User {
  const payload = decodeJwtPayload(token)
  const isAdminFromToken = typeof payload?.isAdmin === 'boolean' ? payload.isAdmin : undefined
  const emailFromToken = typeof payload?.email === 'string' ? payload.email : undefined
  return {
    ...user,
    email: user.email || emailFromToken || user.email,
    isAdmin: typeof user.isAdmin === 'boolean' ? user.isAdmin : isAdminFromToken,
  }
}

async function claimLegacyLocalPlanning(userId: string) {
  try {
    // Claim any legacy items (ownerUserId is null) for current user.
    await db.planning.where('ownerUserId').equals(null as any).modify({ ownerUserId: userId } as any)
  } catch {
    // ignore
  }
}

function tokenExpiresAt(token: string): number | null {
  const payload = decodeJwtPayload(token)
  const exp = typeof payload?.exp === 'number' ? payload.exp : null
  if (!exp) return null
  return exp * 1000
}

const IDLE_TIMEOUT_MS = 30 * 60 * 1000 // 30 minutes

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AuthState | null>(null)
  const idleTimer = useRef<number | null>(null)
  const logoutTimer = useRef<number | null>(null)

  useEffect(() => {
    try {
      const raw = localStorage.getItem(LS_KEY)
      if (!raw) return
      const parsed = JSON.parse(raw) as Partial<AuthState>
      if (!parsed?.token || !parsed?.user?.id) return
      const exp = parsed.expiresAt ?? tokenExpiresAt(parsed.token) ?? 0
      if (!exp || exp <= Date.now()) {
        localStorage.removeItem(LS_KEY)
        return
      }
      const enriched = enrichUserFromToken(parsed.token, parsed.user as User)
      setState({ token: parsed.token, user: enriched, expiresAt: exp })
      void claimLegacyLocalPlanning(enriched.id)
    } catch {
      // ignore
    }
  }, [])

  // Auto logout when token expires
  useEffect(() => {
    if (logoutTimer.current) {
      window.clearTimeout(logoutTimer.current)
      logoutTimer.current = null
    }
    if (!state?.expiresAt) return
    const ms = state.expiresAt - Date.now()
    if (ms <= 0) {
      setState(null)
      localStorage.removeItem(LS_KEY)
      return
    }
    logoutTimer.current = window.setTimeout(() => {
      setState(null)
      localStorage.removeItem(LS_KEY)
    }, ms)
    return () => {
      if (logoutTimer.current) {
        window.clearTimeout(logoutTimer.current)
        logoutTimer.current = null
      }
    }
  }, [state?.expiresAt])

  // Idle timeout: log out after inactivity
  useEffect(() => {
    function resetIdle() {
      if (!state) return
      if (idleTimer.current) window.clearTimeout(idleTimer.current)
      idleTimer.current = window.setTimeout(() => {
        setState(null)
        localStorage.removeItem(LS_KEY)
      }, IDLE_TIMEOUT_MS)
    }

    if (!state) return
    resetIdle()
    const events = ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'] as const
    for (const ev of events) window.addEventListener(ev, resetIdle, { passive: true })

    return () => {
      if (idleTimer.current) {
        window.clearTimeout(idleTimer.current)
        idleTimer.current = null
      }
      for (const ev of events) window.removeEventListener(ev, resetIdle as any)
    }
  }, [state])

  const value = useMemo<AuthContextValue>(
    () => ({
      token: state?.token ?? null,
      user: state?.user ?? null,
      login: (token, user) => {
        const exp = tokenExpiresAt(token)
        // If token is missing exp (shouldn't happen), force a short session
        const expiresAt = exp ?? Date.now() + 60 * 60 * 1000
        const enriched = enrichUserFromToken(token, user)
        const next: AuthState = { token, user: enriched, expiresAt }
        setState(next)
        localStorage.setItem(LS_KEY, JSON.stringify(next))
        void claimLegacyLocalPlanning(enriched.id)
      },
      logout: () => {
        setState(null)
        localStorage.removeItem(LS_KEY)
      },
    }),
    [state],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}


