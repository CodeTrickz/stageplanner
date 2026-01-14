# Traefik Reverse Proxy Setup

Dit project gebruikt Traefik als reverse proxy met Let's Encrypt SSL certificaten.

## Configuratie

### 1. Environment Variabelen

Voeg de volgende variabelen toe aan je `.env` bestand:

```bash
# Domain configuratie
DOMAIN=example.com
SUBDOMAIN=traefik

# Let's Encrypt email
ACME_EMAIL=admin@example.com

# Traefik dashboard authenticatie
# Genereer met: ./generate-traefik-auth.sh admin yourpassword
TRAEFIK_AUTH=admin:$$apr1$$...
```

### 2. Traefik Auth Hash Genereren

Gebruik het helper script om een auth hash te genereren:

```bash
./generate-traefik-auth.sh admin yourpassword
```

Kopieer de output naar `TRAEFIK_AUTH` in je `.env` bestand.

### 3. DNS Configuratie

Zorg ervoor dat je DNS records correct zijn ingesteld:

- **Hoofddomein**: `example.com` → A record naar je server IP
- **Subdomein**: `traefik.example.com` → A record naar je server IP (of CNAME naar hoofddomein)

### 4. Poorten

Traefik luistert op:
- **Poort 80**: HTTP (wordt automatisch doorgestuurd naar HTTPS)
- **Poort 443**: HTTPS

Zorg ervoor dat deze poorten open zijn in je firewall.

## Toegang

- **Web Applicatie**: `https://example.com` (of je ingestelde DOMAIN)
- **Traefik Dashboard**: `https://traefik.example.com` (of je ingestelde SUBDOMAIN)

Het Traefik dashboard is beveiligd met basic auth (gebruik de credentials die je hebt ingesteld in `TRAEFIK_AUTH`).

## SSL Certificaten

Let's Encrypt certificaten worden automatisch aangevraagd en vernieuwd door Traefik. Certificaten worden opgeslagen in `./traefik/letsencrypt/`.

**Belangrijk**: Zorg ervoor dat je domein correct naar je server wijst voordat je de containers start, anders kan Let's Encrypt de certificaten niet aanvragen.

## Troubleshooting

### Certificaten worden niet aangevraagd

1. Controleer of je domein correct naar je server IP wijst
2. Controleer of poorten 80 en 443 open zijn
3. Bekijk de Traefik logs: `docker compose logs traefik`

### Dashboard is niet toegankelijk

1. Controleer of `TRAEFIK_AUTH` correct is ingesteld (met `$$` escapes)
2. Controleer of het subdomein correct is geconfigureerd in DNS
3. Bekijk de Traefik logs voor foutmeldingen

### Web applicatie is niet bereikbaar

1. Controleer of de `web` container draait: `docker compose ps`
2. Controleer of `DOMAIN` correct is ingesteld in `.env`
3. Bekijk de logs: `docker compose logs web traefik`
