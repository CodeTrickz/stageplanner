# Security Verbeteringen - Stage Planner

Dit document bevat een overzicht van security verbeteringen die kunnen worden geïmplementeerd.

## 🔴 Kritieke Verbeteringen

### 1. Helmet Configuratie Verbeteren
**Huidige situatie**: `helmet()` wordt gebruikt zonder specifieke configuratie.

**Aanbeveling**: Configureer Helmet met specifieke security headers:
```typescript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // MUI vereist inline styles
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", process.env.CORS_ORIGIN || 'http://localhost:5173'],
    },
  },
  crossOriginEmbedderPolicy: false, // Voor compatibiliteit
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}))
```

### 2. Admin Seeding in Production
**Probleem**: Default admin credentials worden altijd aangemaakt (regel 206-231 in server.ts).

**Aanbeveling**: 
- Alleen seeden in development/staging
- Check `NODE_ENV !== 'production'` voordat je seed
- Of gebruik een expliciete `SEED_ADMIN=true` flag

```typescript
if (process.env.NODE_ENV !== 'production' || process.env.SEED_ADMIN === 'true') {
  // seed admin
}
```

### 3. Error Information Leakage
**Probleem**: Stack traces en error details kunnen worden gelekt in production.

**Aanbeveling**: Verberg stack traces in production:
```typescript
app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  // ... existing code ...
  const isDev = process.env.NODE_ENV !== 'production'
  appendErrorLog({
    // ... existing fields ...
    stack: isDev ? err?.stack : undefined, // Alleen in dev
  })
  return res.status(500).json({ 
    error: 'server_error',
    ...(isDev ? { details: err.message } : {}) // Alleen in dev
  })
})
```

### 4. CORS Credentials
**Huidige situatie**: `credentials: false` in CORS configuratie.

**Aanbeveling**: Als je cookies/sessions wilt gebruiken, zet `credentials: true` en update CORS:
```typescript
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  credentials: true, // Als je cookies gebruikt
  optionsSuccessStatus: 200
}))
```

### 5. JWT Secret Validatie
**Verbetering**: Valideer dat JWT_SECRET minimaal 32 karakters is:
```typescript
export function getJwtSecret() {
  const secret = process.env.JWT_SECRET
  if (!secret) throw new Error('Missing JWT_SECRET')
  if (secret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long')
  }
  return secret
}
```

## 🟡 Belangrijke Verbeteringen

### 6. Rate Limiting Verbeteren
**Huidige situatie**: Basic rate limiting is aanwezig, maar kan uitgebreid worden.

**Aanbeveling**: 
- Voeg rate limiting toe aan alle endpoints (niet alleen auth)
- Gebruik een library zoals `express-rate-limit` voor betere controle
- Implementeer progressive delays bij herhaalde violations

### 7. Input Sanitization
**Huidige situatie**: Zod validatie is aanwezig, maar geen HTML sanitization.

**Aanbeveling**: Voor user-generated content (notes, planning titles):
```typescript
import DOMPurify from 'isomorphic-dompurify' // of dompurify voor browser

// In note/planning schemas:
body: z.string().max(200000).transform((val) => DOMPurify.sanitize(val))
```

### 8. SQL Injection Prevention
**Huidige situatie**: ✅ Goed - better-sqlite3 gebruikt prepared statements.

**Aanbeveling**: Blijf alert op direct string concatenation in queries.

### 9. Password Policy
**Huidige situatie**: Basic password strength check (10+ chars, letter + number).

**Aanbeveling**: Versterk password policy:
- Minimum 12 karakters
- Minimaal 1 hoofdletter
- Minimaal 1 speciaal karakter
- Check tegen common passwords (Have I Been Pwned API)

### 10. Session Management
**Huidige situatie**: JWT tokens met refresh tokens.

**Aanbeveling**: 
- Implementeer token revocation list
- Voeg device fingerprinting toe
- Log alle token activiteit voor audit

### 11. CSRF Protection
**Huidige situatie**: Geen CSRF protection.

**Aanbeveling**: Voor state-changing requests:
```typescript
import csrf from 'csurf'
const csrfProtection = csrf({ cookie: true })
app.use(csrfProtection)
```

### 12. File Upload Security
**Huidige situatie**: Files worden opgeslagen in IndexedDB (client-side).

**Aanbeveling**: Als je server-side uploads toevoegt:
- Valideer file types (whitelist)
- Limiteer file size
- Scan voor malware
- Sanitize filenames
- Store buiten webroot

### 13. Email Verification Token Expiry
**Huidige situatie**: 24 uur expiry (goed).

**Aanbeveling**: 
- Verkort naar 1 uur voor betere security
- Implementeer token reuse detection

### 14. Audit Logging Verbeteren
**Huidige situatie**: Audit logging is aanwezig.

**Aanbeveling**: 
- Log alle failed login attempts
- Log password change attempts
- Log admin actions met extra detail
- Implementeer log rotation

### 15. Environment Variables Validatie
**Aanbeveling**: Valideer alle required env vars bij startup:
```typescript
const requiredEnvVars = ['JWT_SECRET', 'APP_URL', 'CORS_ORIGIN']
for (const varName of requiredEnvVars) {
  if (!process.env[varName]) {
    throw new Error(`Missing required environment variable: ${varName}`)
  }
}
```

## 🟢 Aanbevolen Verbeteringen

### 16. Security Headers
**Aanbeveling**: Voeg extra security headers toe:
```typescript
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('X-XSS-Protection', '1; mode=block')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
  next()
})
```

### 17. Request Size Limits
**Huidige situatie**: 2MB limit voor JSON.

**Aanbeveling**: 
- Verlaag naar 1MB voor normale requests
- Specifieke limits per endpoint
- Rate limit op basis van request size

### 18. IP Whitelisting (Optioneel)
**Aanbeveling**: Voor admin endpoints:
```typescript
const adminIpWhitelist = process.env.ADMIN_IP_WHITELIST?.split(',') || []
function requireAdminIp(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (adminIpWhitelist.length > 0 && !adminIpWhitelist.includes(req.ip)) {
    return res.status(403).json({ error: 'forbidden' })
  }
  next()
}
```

### 19. Dependency Updates
**Aanbeveling**: 
- Run `npm audit` regelmatig
- Update dependencies maandelijks
- Gebruik Dependabot (al geconfigureerd)
- Check voor known vulnerabilities

### 20. Database Encryption
**Aanbeveling**: Voor gevoelige data in SQLite:
- Overweeg encryptie op applicatie niveau
- Of gebruik SQLCipher voor encrypted SQLite

### 21. Logging Security
**Aanbeveling**: 
- Log geen passwords of tokens
- Sanitize user input in logs
- Implementeer log retention policy
- Secure log file permissions

### 22. API Versioning
**Aanbeveling**: Implementeer API versioning:
```typescript
app.use('/api/v1', routes)
```

### 23. Health Check Verbetering
**Aanbeveling**: Voeg database health check toe:
```typescript
app.get('/health', async (_req, res) => {
  try {
    // Check database connection
    db.listUsers() // Simple query
    res.json({ ok: true, database: 'connected' })
  } catch (error) {
    res.status(503).json({ ok: false, database: 'disconnected' })
  }
})
```

### 24. Frontend Security
**Aanbeveling**: 
- Implementeer Content Security Policy (CSP)
- Sanitize alle user input in React
- Valideer data client-side EN server-side
- Gebruik HTTPS in production

### 25. Monitoring & Alerting
**Aanbeveling**: 
- Monitor failed login attempts
- Alert bij verdachte activiteit
- Track rate limit violations
- Monitor error rates

## 📋 Implementatie Prioriteit

1. **Direct implementeren** (Kritiek):
   - Helmet configuratie
   - Admin seeding fix
   - Error information leakage
   - JWT secret validatie

2. **Binnen 1 week** (Belangrijk):
   - Rate limiting verbeteren
   - Input sanitization
   - Password policy
   - Environment variables validatie

3. **Binnen 1 maand** (Aanbevolen):
   - CSRF protection
   - Security headers
   - Audit logging verbeteren
   - Monitoring setup

## 🔍 Security Testing

**Aanbeveling**: Voeg security tests toe:
- Penetration testing
- Dependency scanning
- SAST (Static Application Security Testing)
- DAST (Dynamic Application Security Testing)

## 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [Helmet Documentation](https://helmetjs.github.io/)



