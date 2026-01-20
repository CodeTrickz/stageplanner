# Changelog

## [Unreleased]

### Added
- Workspace-scoped sync for planning, notes, and files
- Realtime push layer via SSE (`/events`)
- Workspace selector visible in top bar and settings
- Internship day tracking (workday vs home) with dashboard progress

### Changed
- Files are stored server-side (SQLite BLOBs)
- Notes sharing UI removed
- Week planning cards made more readable

### Fixed
- Internship progress on dashboard works even with mixed tag formats
- CI lint failure caused by unused Dexie upgrade transactions
