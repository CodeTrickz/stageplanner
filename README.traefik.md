# Traefik Reverse Proxy Setup

This project uses Traefik v2.10 as a reverse proxy with Let's Encrypt SSL certificates, Prometheus metrics, and Jaeger tracing.

## Configuration

### 1. Environment variables

Add the following to your `.env` file:

```bash
# Domain configuration
DOMAIN=example.com
SUBDOMAIN=traefik

# Let's Encrypt email
ACME_EMAIL=admin@example.com

# Traefik dashboard authentication
# Generate with: ./generate-traefik-auth.sh admin yourpassword
TRAEFIK_AUTH=admin:$$apr1$$...
```

### 2. Generate Traefik auth hash

Use the helper script:

```bash
./generate-traefik-auth.sh admin yourpassword
```

Copy the output to `TRAEFIK_AUTH` in your `.env`.

### 3. DNS configuration

Ensure your DNS records are correct:

- **Root domain**: `example.com` → A record to your server IP
- **Subdomain**: `traefik.example.com` → A record to your server IP (or CNAME to root domain)

### 4. Ports

Traefik listens on:

- **Port 80**: HTTP (redirects to HTTPS)
- **Port 443**: HTTPS

Open these ports in your firewall.

## Access

- **Web app**: `https://example.com` (or your DOMAIN)
- **Traefik dashboard**: `https://traefik.example.com` (or your SUBDOMAIN)
- **Prometheus**: `https://metrics.example.com` (if enabled)
- **Jaeger UI**: `https://tracing.example.com`

The Traefik dashboard, Prometheus, and Jaeger UI are protected by basic auth (use the credentials in `TRAEFIK_AUTH`).

## SSL Certificates

Let's Encrypt certificates are automatically issued and renewed by Traefik. Certificates are stored in `./traefik/letsencrypt/`.

**Important**: Make sure your domain points to your server before starting containers, or Let's Encrypt cannot issue certificates.

## Troubleshooting

### Certificates are not issued

1. Check that your domain points to your server IP
2. Check that ports 80 and 443 are open
3. Review Traefik logs: `docker compose logs traefik`

### Dashboard is not accessible

1. Check that `TRAEFIK_AUTH` is correct (with `$$` escapes)
2. Check that the subdomain DNS is correct
3. Review Traefik logs

### Web app is not reachable

1. Check that the `web` container is running: `docker compose ps`
2. Check that `DOMAIN` is set correctly in `.env`
3. Review logs: `docker compose logs web traefik`

### Tracing or metrics are not reachable

1. Check that `prometheus` and `jaeger` are running
2. Check that `metrics.<DOMAIN>` and `tracing.<DOMAIN>` exist in DNS
3. Review logs: `docker compose logs prometheus jaeger`
