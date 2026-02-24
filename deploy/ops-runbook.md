# SecuShare Operations Runbook

## Backup Strategy

### What to back up

1. **SQLite database** (`/opt/secushare/data/secushare.db`)
   - Contains user accounts, file metadata, share records, guest sessions.
   - WAL mode is enabled; back up both `.db` and `.db-wal` files together.

2. **Encrypted file storage** (`/opt/secushare/storage/files/`)
   - Contains AES-256-GCM encrypted file blobs. Filenames are UUIDs.

3. **Environment/secrets** (`/etc/secushare/secushare.env`)
   - Contains JWT_SECRET and other configuration. Store separately in a secrets manager.

### Backup procedure

```bash
# Stop writes (optional but recommended for consistency)
systemctl stop secushare

# SQLite safe backup using .backup command (works even with WAL)
sqlite3 /opt/secushare/data/secushare.db ".backup /backups/secushare-$(date +%Y%m%d).db"

# Sync encrypted files
rsync -a /opt/secushare/storage/files/ /backups/uploads/

# Restart
systemctl start secushare
```

For zero-downtime backups, use SQLite's online backup API or `VACUUM INTO`:
```bash
sqlite3 /opt/secushare/data/secushare.db "VACUUM INTO '/backups/secushare-$(date +%Y%m%d).db';"
```

### Schedule

- **Database**: Daily, retain 30 days.
- **File storage**: Daily incremental (rsync), weekly full. Retain 30 days.
- **Off-site**: Replicate backups to a remote location or object storage.

### Restore procedure

```bash
systemctl stop secushare
cp /backups/secushare-YYYYMMDD.db /opt/secushare/data/secushare.db
rsync -a /backups/uploads/ /opt/secushare/storage/files/
chown -R secushare:secushare /opt/secushare/
systemctl start secushare
```

## Certificate Renewal

Certbot auto-renews Let's Encrypt certificates via a systemd timer.

```bash
# Verify timer is active
systemctl list-timers | grep certbot

# Test renewal
certbot renew --dry-run

# Force renewal (if needed)
certbot renew --force-renewal
```

Certbot's nginx plugin automatically reloads nginx after renewal.

## Health Checks

- Liveness: `GET /health` (returns 200 if process is running)
- Readiness: `GET /health/ready` (returns 200 if DB and storage are accessible)
- Metrics: `GET /metrics` (Prometheus format; disabled by default in production)
  - If enabled in production, send `Authorization: Bearer <METRICS_TOKEN>`

## Post-Deploy Smoke Test

Run the scripted smoke checks from your deployment host:

```powershell
# Requires Windows PowerShell 5.1+ (or PowerShell 7+)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/prod-smoke-test.ps1 `
  -ApiBaseUrl "http://127.0.0.1:8080/api/v1" `
  -HealthBaseUrl "http://127.0.0.1:8080" `
  -MetricsMode "disabled"
```

If metrics are enabled in production, run with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/prod-smoke-test.ps1 `
  -MetricsMode "enabled" `
  -MetricsToken "<METRICS_TOKEN>"
```

## Log Locations

- Application: stdout/journald (`journalctl -u secushare`)
- Nginx access: `/var/log/nginx/secushare-access.log`
- Nginx error: `/var/log/nginx/secushare-error.log`
- Audit events: Tagged with `"log_type":"audit"` in application logs
