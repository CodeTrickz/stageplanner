import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from './auth'

export function RequireAuth() {
  const { token } = useAuth()
  const loc = useLocation()
  if (!token) {
    const redirect = encodeURIComponent(loc.pathname + loc.search)
    return <Navigate to={`/login?next=${redirect}`} replace />
  }
  return <Outlet />
}










