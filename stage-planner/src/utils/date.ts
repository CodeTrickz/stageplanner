export function yyyyMmDdLocal(d: Date) {
  // en-CA geeft standaard YYYY-MM-DD
  return d.toLocaleDateString('en-CA')
}

export function dateFromYmdLocal(ymd: string) {
  const [y, m, d] = ymd.split('-').map((x) => Number(x))
  return new Date(y, (m ?? 1) - 1, d ?? 1)
}

export function ymdFromParts(year: number, monthIndex0: number, day: number) {
  const m = String(monthIndex0 + 1).padStart(2, '0')
  const dd = String(day).padStart(2, '0')
  return `${year}-${m}-${dd}`
}

export function addDays(d: Date, days: number) {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() + days)
}

export function startOfWeekMonday(d: Date) {
  // JS: 0=Sun..6=Sat. We want Monday as first day.
  const day = d.getDay()
  const diff = (day + 6) % 7
  return addDays(d, -diff)
}

export function startOfWeekSunday(d: Date) {
  const day = d.getDay()
  return addDays(d, -day)
}

export function minutesToTime(m: number) {
  const hh = String(Math.floor(m / 60)).padStart(2, '0')
  const mm = String(m % 60).padStart(2, '0')
  return `${hh}:${mm}`
}

export function formatTimeHm(hm: string, opts?: { format?: '24h' | '12h' }) {
  const fmt = opts?.format ?? '24h'
  if (fmt === '24h') return hm
  const [hhStr, mmStr] = String(hm || '').split(':')
  const hh = Number(hhStr)
  const mm = Number(mmStr)
  if (!Number.isFinite(hh) || !Number.isFinite(mm)) return hm
  const h12 = ((hh + 11) % 12) + 1
  const ampm = hh >= 12 ? 'PM' : 'AM'
  return `${h12}:${String(mm).padStart(2, '0')} ${ampm}`
}

export function formatTimeRange(start: string, end: string, opts?: { format?: '24h' | '12h' }) {
  return `${formatTimeHm(start, opts)}–${formatTimeHm(end, opts)}`
}


