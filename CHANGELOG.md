# Changelog

## [Unreleased]

### Added
- Jaeger tracing for backend and Traefik (native Jaeger in Traefik v2.10)
- Prometheus scraping for Traefik + backend metrics
- Admin tools to wipe audit and error logs
- Stage day tracking (workday vs home) with dashboard progress
- Week overview always shows 7 days without horizontal scroll
- Planning delete now removes remote items

### Changed
- Traefik configuration updated for Prometheus + Jaeger dashboards
- Navigation layout updated to GitHub-style tabs with icons
- Workspace seeding now keeps only admin by default

### Fixed
- Fixed planning tag sync so stage day type persists
- Removed obsolete migration plan doc from repo

### Technical
- Updated theme with mobile-first typography and component overrides
- Improved responsive spacing and padding throughout
- Better button and form field sizing for mobile devices
- Enhanced drawer menu for mobile/tablet navigation




