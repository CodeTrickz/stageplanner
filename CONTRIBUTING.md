# Bijdragen aan Stage Planner

Bedankt voor je interesse om bij te dragen aan Stage Planner! Dit document bevat richtlijnen en informatie over hoe je kunt bijdragen.

## 📋 Code of Conduct

We verwachten dat alle contributors respectvol en professioneel zijn. Wees vriendelijk en constructief in alle interacties.

## 🚀 Hoe te Bijdragen

### Bug Reports

Als je een bug hebt gevonden:

1. Check of er al een [issue](../../issues) bestaat voor deze bug
2. Als niet, maak een nieuwe issue aan met:
   - Duidelijke beschrijving van het probleem
   - Stappen om te reproduceren
   - Verwachte vs. werkelijke gedrag
   - Screenshots (indien van toepassing)
   - Je omgeving (OS, browser, Node versie)

### Feature Requests

Voor nieuwe features:

1. Check of er al een [issue](../../issues) bestaat voor deze feature
2. Maak een nieuwe issue aan met:
   - Beschrijving van de gewenste feature
   - Use case / motivatie
   - Eventuele voorbeelden of mockups

### Pull Requests

1. **Fork de repository**
2. **Maak een feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Volg de code style**
   - Gebruik TypeScript strict mode
   - Volg bestaande code formatting
   - Voeg comments toe waar nodig
4. **Test je wijzigingen**
   - Test lokaal
   - Zorg dat de build werkt (`npm run build`)
   - Zorg dat linting slaagt (`npm run lint`)
5. **Commit je wijzigingen**
   ```bash
   git commit -m "feat: add amazing feature"
   ```
   Gebruik [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` voor nieuwe features
   - `fix:` voor bug fixes
   - `docs:` voor documentatie
   - `style:` voor formatting
   - `refactor:` voor code refactoring
   - `test:` voor tests
   - `chore:` voor andere wijzigingen
6. **Push naar je fork**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open een Pull Request**
   - Beschrijf duidelijk wat je hebt gewijzigd en waarom
   - Link naar gerelateerde issues
   - Voeg screenshots toe voor UI wijzigingen

## 🎨 Code Style

### TypeScript

- Gebruik TypeScript strict mode
- Vermijd `any` types
- Gebruik expliciete return types voor functies
- Gebruik interfaces voor object types

### React

- Gebruik function components met hooks
- Gebruik TypeScript voor props
- Houd components klein en focused
- Gebruik meaningful namen

### Naming Conventions

- Components: PascalCase (`MyComponent.tsx`)
- Functions/variables: camelCase (`myFunction`)
- Constants: UPPER_SNAKE_CASE (`API_BASE_URL`)
- Files: kebab-case of PascalCase voor components

## 🧪 Testing

Voordat je een PR indient:

- Test je wijzigingen lokaal
- Zorg dat alle bestaande functionaliteit nog werkt
- Test op verschillende browsers (indien mogelijk)
- Zorg dat de CI build slaagt

## 📝 Documentatie

- Update README.md als je nieuwe features toevoegt
- Voeg comments toe bij complexe code
- Update CHANGELOG.md voor user-facing wijzigingen

## 🔍 Review Proces

1. Een maintainer zal je PR reviewen
2. Feedback kan worden gegeven - wees open voor suggesties
3. Na goedkeuring wordt je PR gemerged

## ❓ Vragen?

Als je vragen hebt, open een [discussion](../../discussions) of een [issue](../../issues).

Bedankt voor je bijdrage! 🎉




