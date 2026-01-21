# Changelog

## [Unreleased]

### Added
- Workspace-scoped sync for planning, notes, and files
- Realtime push layer via SSE (`/events`)
- Workspace selector visible in top bar and settings
- Internship day tracking (workday vs home) with dashboard progress
- Forgot password flow with reset page
- Idle logout configuration via `VITE_IDLE_LOGOUT_MINUTES`
- Server-side cache with ETag/If-None-Match for planning, notes, and files
- Cache smoke test script (`testscripts/cache-smoke.sh`)
- Bulk actions for planning items (multi-select + status/priority/tags update)
- Stage report export (PDF/CSV) from the dashboard
- Workspace roles (owner/editor/commenter/viewer) with permission checks
- Workspace task templates (apply to a week)

### Changed
- Files are stored server-side (SQLite BLOBs)
- Notes sharing UI removed
- Week planning cards made more readable
- Stage workday progress counts only after the time slot has passed
- Cache TTL configurable via `CACHE_TTL_SECONDS` (default 30s)
- Stage report export includes hours, completed totals, and weekly status breakdown

### Fixed
- Internship progress on dashboard works even with mixed tag formats
- CI lint failure caused by unused Dexie upgrade transactions
- Stage workday tags no longer show legacy "non-workday" label
