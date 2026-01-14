# Security Policy

## 🔒 Supported Versions

We ondersteunen security updates voor de laatste stabiele versie van Stage Planner.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < Latest| :x:                |

## 🚨 Reporting a Vulnerability

Als je een security vulnerability hebt gevonden, **open GEEN public issue**. In plaats daarvan:

1. **Email**: Stuur een email naar de maintainers (voeg email toe indien beschikbaar)
2. **GitHub Security Advisory**: Gebruik [GitHub's private vulnerability reporting](https://github.com/OWNER/REPO/security/advisories/new) indien beschikbaar

### Wat te Includeren

- Beschrijving van de vulnerability
- Stappen om te reproduceren
- Potentiële impact
- Suggesties voor fix (indien mogelijk)

### Response Tijd

- We proberen binnen **48 uur** te reageren
- We houden je op de hoogte van de status
- Na fix wordt een security advisory gepubliceerd (indien van toepassing)

## 🛡️ Security Best Practices

### Voor Developers

- Gebruik altijd de laatste dependencies
- Run `npm audit` regelmatig
- Gebruik environment variables voor secrets
- Valideer alle user input
- Gebruik parameterized queries (SQL injection prevention)
- Implementeer rate limiting waar nodig

### Voor Users

- Gebruik sterke wachtwoorden
- Houd je JWT_SECRET geheim
- Gebruik HTTPS in production
- Update regelmatig naar de laatste versie

## 🔐 Known Security Considerations

- JWT tokens worden gebruikt voor authenticatie - zorg voor sterke `JWT_SECRET`
- SQLite database - overweeg encryptie voor gevoelige data
- CORS is geconfigureerd - pas `CORS_ORIGIN` aan voor production
- Email verificatie - configureer SMTP voor production gebruik

## 📚 Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)







