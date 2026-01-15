# Stage Planner

Een moderne planning applicatie met backend en frontend, gebouwd met React, TypeScript, Express en SQLite.

## 📋 Overzicht

Stage Planner is een full-stack applicatie voor dagplanning, bestandsbeheer en notities. De applicatie bestaat uit:

- **Frontend**: React + TypeScript (Vite) met Material UI
- **Backend**: Express + TypeScript met SQLite database
- **Storage**: IndexedDB voor client-side opslag, SQLite voor server-side data

## 🚀 Quick Start

### Vereisten

- Node.js 20+
- npm of yarn
- Docker (optioneel, voor production deployment)

### Lokale Development

1. **Clone de repository**
   ```bash
   git clone <repository-url>
   cd stageplanner
   ```

2. **Backend opstarten**
   ```bash
   cd backend
   npm install
   npm run dev
   ```
   Backend draait op `http://localhost:3001`

3. **Frontend opstarten** (in een nieuwe terminal)
   ```bash
   cd stage-planner
   npm install
   npm run dev
   ```
   Frontend opent op `http://localhost:5173`

### Docker Deployment

Zie [README.docker.md](./README.docker.md) voor instructies om de applicatie met Docker Compose (Traefik + Prometheus + Jaeger) te draaien.

## 📁 Project Structuur

```
.
├── backend/           # Express backend (TypeScript)
│   ├── src/          # Source code
│   ├── data/         # SQLite databases (gitignored)
│   └── prisma/       # Database schema (indien gebruikt)
├── stage-planner/    # React frontend (TypeScript)
│   ├── src/          # Source code
│   │   ├── api/      # API client
│   │   ├── auth/     # Authentication
│   │   ├── components/ # React components
│   │   ├── pages/    # Page components
│   │   └── utils/    # Utility functions
│   └── public/       # Static assets
├── .github/          # GitHub workflows en templates
└── docker-compose.yml # Docker Compose configuratie
```

## 🔧 Configuratie

### Backend

Kopieer `backend/env.example` naar `backend/env.local` en pas aan:

- `JWT_SECRET`: Lange random string voor JWT tokens
- `APP_URL`: Public URL van de applicatie (voor verificatie emails)
- `CORS_ORIGIN`: CORS origin (moet matchen met frontend URL)
- `SMTP_HOST/SMTP_USER/SMTP_PASS`: SMTP configuratie voor echte emails
- `MAIL_FROM`: Afzenderadres voor emails (optioneel, default = `SMTP_USER`)

#### Admin Gebruiker

De applicatie maakt automatisch een default admin gebruiker aan bij het opstarten (in development mode of als `SEED_ADMIN=true` is ingesteld).

**Default credentials:**
- **Email**: `admin@app.be`
- **Username**: `admin`
- **Password**: `admin`

Je kunt deze aanpassen via environment variables in `backend/env.local`:
- `SEED_ADMIN=true` - Zet op `true` om admin seeding in te schakelen (standaard aan in development)
- `ADMIN_EMAIL=admin@app.be` - Admin email adres
- `ADMIN_USERNAME=admin` - Admin gebruikersnaam
- `ADMIN_PASSWORD=admin` - Admin wachtwoord

**⚠️ Belangrijk voor productie:**
- Wijzig de admin credentials in productie via `.env` bestand
- Of zet `SEED_ADMIN=false` en maak handmatig een admin gebruiker aan via de API

### Frontend

De frontend gebruikt environment variables via Vite. Zie `stage-planner/.env.example` (indien aanwezig).

## 🧪 Development

### Backend Scripts

- `npm run dev` - Start development server met hot reload
- `npm run build` - Build voor production
- `npm start` - Start production server

### Frontend Scripts

- `npm run dev` - Start development server
- `npm run build` - Build voor production
- `npm run lint` - Run ESLint
- `npm run preview` - Preview production build

## 📝 Features

- ✅ Dashboard met planning-overzichten
- ✅ Dagplanning met tijdsindeling
- ✅ Weekoverzicht (7 dagen)
- ✅ Taken-overzicht met filters
- ✅ Bestandsbeheer (upload/download via IndexedDB)
- ✅ Notities met bijlagen
- ✅ Export functionaliteit (.txt, .zip)
- ✅ User authenticatie en verificatie
- ✅ Responsive design (mobile-first)
- ✅ Admin functionaliteit
- ✅ Stage-dag tracking (werkdagen vs thuisdagen)

## 🤝 Bijdragen

Zie [CONTRIBUTING.md](./CONTRIBUTING.md) voor richtlijnen over hoe je kunt bijdragen aan dit project.

## 📄 Licentie

Zie [LICENSE](./LICENSE) voor licentie informatie.

## 🔒 Security

Zie [SECURITY.md](./SECURITY.md) voor informatie over security vulnerabilities en hoe deze te melden.

## 📚 Documentatie

- [Docker Deployment](./README.docker.md)
- [Traefik Setup](./README.traefik.md)
- [Changelog](./CHANGELOG.md)
- [Frontend README](./stage-planner/README.md)

## 🛠️ Tech Stack

### Frontend
- React 18
- TypeScript
- Vite
- Material UI (MUI)
- Dexie (IndexedDB)
- React Router

### Backend
- Express
- TypeScript
- SQLite (better-sqlite3)
- JWT authentication
- Nodemailer

## 📞 Support

Voor vragen of problemen, open een [issue](../../issues) op GitHub.

