# Changelog

## [Unreleased]

- No changes yet.

## [1.0.2] - 2026-01-28

### Fixed
- Fixed "too many requests" error when duplicating days
- Optimized workspace events handling to only refresh planning items for planning events (not all 5 useEffect hooks)
- Added debouncing (800ms) for planning events to prevent rate limiting
- Improved HTML layout structure for planning page boxes

### Changed
- Increased API rate limit from 100 to 200 requests per 15 minutes for better UX
- Increased auth rate limit from 30 to 50 requests per 15 minutes

## [1.0.1] - 2026-01-28

### Fixed
- Fixed rate limiting issue in global search function
- Improved search debouncing from 250ms to 500ms to reduce API calls
- Removed automatic search triggers on workspace events to prevent unnecessary API requests
- Added parameter validation to prevent duplicate API calls with same search parameters

## [1.0.0] - 2026-01-27

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
- Bulk delete for planning and tasks overview
- Stage report export (PDF/CSV) from the dashboard
- Workspace roles (owner/editor/commenter/viewer) with permission checks
- Workspace task templates (apply to a week + manage in planning)
- Template fields for priority/status + stage day tagging
- Deadline notifications (in-app) with optional email delivery
- Global search across planning, notes, and files with filters and sort order
- Rate-limit UX toast with retry-after messaging
- Client error log viewer + detail dialog in settings

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
