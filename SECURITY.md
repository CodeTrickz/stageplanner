# Security Policy

## Supported Versions

We provide security updates for the latest stable version of Stage Planner.

| Version | Supported |
| ------- | --------- |
| 1.0.1   | ✅        |
| 1.0.0   | ✅        |
| < 1.0.0 | ❌        |

## Reporting a Vulnerability

If you find a security vulnerability, **do NOT open a public issue**. Instead:

1. **Email**: contact the maintainers (add an email if available)
2. **GitHub Security Advisory**: use [GitHub's private vulnerability reporting](https://github.com/CodeTrickz/stageplanner/security/advisories/new)

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if possible)

### Response time

- We aim to respond within **48 hours**
- We will keep you updated on the status
- A security advisory will be published after a fix (if applicable)

## Security Best Practices

### For developers

- Keep dependencies up to date
- Run `npm audit` regularly
- Use environment variables for secrets
- Validate all user input
- Use parameterized queries (SQL injection prevention)
- Implement rate limiting where needed

### For users

- Use strong passwords
- Keep your `JWT_SECRET` private
- Use HTTPS in production
- Update regularly to the latest version

## Known Security Considerations

- JWT tokens are used for authentication — use a strong `JWT_SECRET`
- SQLite database — consider encryption for sensitive data
- CORS is configured — adjust `CORS_ORIGIN` for production
- Email verification — configure SMTP for production use

## Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
