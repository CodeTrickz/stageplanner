# Changelog

## [Unreleased]

### Added
- Workspace-scoped sync for planning, notes, and files
- Realtime push layer via SSE (`/events`)
- Workspace selector visible in top bar and settings
- Internship day tracking (workday vs home) with dashboard progress
- Forgot password flow with reset page
- Idle logout configuration via `VITE_IDLE_LOGOUT_MINUTES`

### Changed
- Files are stored server-side (SQLite BLOBs)
- Notes sharing UI removed
- Week planning cards made more readable
- Stage workday progress counts only after the time slot has passed

### Fixed
- Internship progress on dashboard works even with mixed tag formats
- CI lint failure caused by unused Dexie upgrade transactions
- Stage workday tags no longer show legacy "non-workday" label
