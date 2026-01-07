# Changelog

## [Unreleased]

### Added
- Mobile-first responsive design throughout the application
- Improved navigation with responsive breakpoints for mobile, tablet, and desktop
- Username display in navigation bar (replaces email)
- Enhanced TypeScript type safety (removed all `any` types)
- Better error handling with proper type guards

### Changed
- **Breaking**: All styling is now mobile-first (base styles for mobile, enhanced for larger screens)
- Navigation bar shows username instead of email
- App title shortened to "Planner" in navigation
- Improved responsive breakpoints:
  - Mobile: < 600px
  - Tablet: 600px - 960px  
  - Desktop: ≥ 960px
- TypeScript target updated to ES2021 (for `replaceAll` support)
- CI workflow improved with separate cache steps for backend and frontend

### Fixed
- All TypeScript compilation errors
- All ESLint errors (95 errors fixed)
- React hooks exhaustive-deps warnings
- Control character regex issues
- Dexie query type issues
- PDF.js type compatibility issues

### Technical
- Updated theme with mobile-first typography and component overrides
- Improved responsive spacing and padding throughout
- Better button and form field sizing for mobile devices
- Enhanced drawer menu for mobile/tablet navigation



