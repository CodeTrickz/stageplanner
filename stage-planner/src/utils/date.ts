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


