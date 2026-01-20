# Contributing to Stage Planner

Thanks for your interest in contributing to Stage Planner! This document outlines guidelines and information for contributors.

## Code of Conduct

We expect all contributors to be respectful and professional. Be friendly and constructive in all interactions.

## How to Contribute

### Bug Reports

If you found a bug:

1. Check if there is already an [issue](../../issues)
2. If not, open a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Screenshots (if applicable)
   - Your environment (OS, browser, Node version)

### Feature Requests

For new features:

1. Check if there is already an [issue](../../issues)
2. Open a new issue with:
   - Description of the requested feature
   - Use case / motivation
   - Examples or mockups (if possible)

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Follow code style**
   - Use TypeScript strict mode
   - Follow existing formatting
   - Add comments where needed
4. **Test your changes**
   - Test locally
   - Ensure build works (`npm run build`)
   - Ensure linting passes (`npm run lint`)
5. **Commit your changes**
   ```bash
   git commit -m "feat: add amazing feature"
   ```
   Use [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation
   - `style:` for formatting
   - `refactor:` for refactors
   - `test:` for tests
   - `chore:` for other changes
6. **Push to your fork**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**
   - Clearly describe what you changed and why
   - Link related issues
   - Add screenshots for UI changes

## Code Style

### TypeScript

- Use TypeScript strict mode
- Avoid `any` types
- Use explicit return types for functions
- Use interfaces for object types

### React

- Use function components with hooks
- Use TypeScript for props
- Keep components small and focused
- Use meaningful names

### Naming Conventions

- Components: PascalCase (`MyComponent.tsx`)
- Functions/variables: camelCase (`myFunction`)
- Constants: UPPER_SNAKE_CASE (`API_BASE_URL`)
- Files: kebab-case or PascalCase for components

## Testing

Before opening a PR:

- Test changes locally
- Ensure existing functionality still works
- Test in multiple browsers if possible
- Ensure CI passes

## Documentation

- Update `README.md` when adding features
- Add comments for complex code
- Update `CHANGELOG.md` for user-facing changes

## Review Process

1. A maintainer will review your PR
2. Feedback may be provided — be open to suggestions
3. After approval, your PR will be merged

## Questions

If you have questions, open a [discussion](../../discussions) or an [issue](../../issues).
