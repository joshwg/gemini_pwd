# Gemini PWD

A secure password manager built with Go that provides encrypted storage of passwords with user management and tagging features.

## Security Features

- **Database-backed sessions** - Sessions persist across server restarts
- **Rate limiting on login attempts** - Protection against brute force attacks
- **Security headers** - XSS, clickjacking, and MIME sniffing protection
- **Session invalidation on password change** - Automatic logout on password changes
- **AES-256 encryption** - All passwords encrypted with unique salts
- **Secure cookies** - HttpOnly and SameSite protection

## Building

### Prerequisites
- Go 1.21 or later
- C compiler (for SQLite support via CGO)

### Quick Build

**Linux/WSL:**
```bash
./build.sh
```

**Windows:**
```cmd
# Try building natively (requires C compiler)
build.bat

# OR use WSL (recommended - always works)
wsl CGO_ENABLED=1 go build -o gemini-pwd
```

### Manual Build Commands

**Linux/WSL:**
```bash
CGO_ENABLED=1 go build -o gemini-pwd
```

**Windows with C compiler:**
```powershell
$env:CGO_ENABLED=1; go build -o gemini-pwd.exe
```

**Windows without C compiler (use WSL):**
```powershell
wsl CGO_ENABLED=1 go build -o gemini-pwd
```

### Running

**Linux/WSL:**
```bash
./gemini-pwd
```

**Windows (if native build succeeded):**
```cmd
gemini-pwd.exe
```

**Windows via WSL (recommended):**
```powershell
wsl ./gemini-pwd
```

## Why CGO is Required

This application uses SQLite via the `go-sqlite3` driver, which requires CGO (C bindings). Without CGO, you'll get the error:
```
Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work
```

**Solutions:**
1. **Use WSL** (easiest on Windows)
2. **Install a C compiler** on Windows (TDM-GCC, MinGW-w64, or Visual Studio Build Tools)
3. **Use Visual Studio** (has built-in C compiler support)

## Setup

1. Install dependencies:
   ```bash
   go mod tidy
   ```

2. Build the application (see Building section above)

3. Create the data directory:
   ```bash
   mkdir ../data     # Linux/WSL
   mkdir ..\data     # Windows
   ```

4. Run the application:
   ```bash
   ./gemini-pwd      # Linux/WSL
   gemini-pwd.exe    # Windows
   ```

5. Open your browser to `http://localhost:7000`

## Default Credentials

- Username: `super`
- Password: `abcd1234`

**⚠️ IMPORTANT: Change the default password immediately after first login!**

## Rate Limiting

- **3 failed attempts**: 30-second cooldown
- **6+ failed attempts**: 5-minute cooldown

## Environment Variables

- `PWD_SECRET_KEY`: **REQUIRED** - Must be exactly 32 bytes. Used for AES-256-GCM encryption of all passwords. Application will refuse to start without it.

  **⚠️ CRITICAL: Store this key securely! If you lose it, all encrypted passwords become permanently unrecoverable.**

- `PWD_DB_FILE`: **REQUIRED** - Absolute path to the SQLite database file. There is no default; the application refuses to start if it is unset or relative. The file is created on first run if it doesn't exist, but its directory must already exist.

- `PWD_BIND_ADDR`: Optional - Interface to listen on (default: `127.0.0.1`, loopback only). The server is meant to sit behind an HTTPS reverse proxy on the same host. Set to `0.0.0.0` to listen on all interfaces (e.g. to reach a WSL dev server from Windows).

- `PWD_INSECURE_COOKIES`: Optional - Set to `1` to drop the `Secure` flag from session cookies. **Development only**, for plain-HTTP access via a non-localhost hostname. Not needed behind an HTTPS proxy, nor for `http://localhost` in Chrome/Firefox. Logs a warning at startup when set.

- `PORT`: Optional - Server port (default: `7000`)
  
  **To run on a different port:**
  ```bash
  # Linux/WSL
  PORT=8080 ./gemini-pwd
  
  # Windows PowerShell
  $env:PORT="8080"; .\gemini-pwd.exe
  
  # Windows Command Prompt
  set PORT=8080 && gemini-pwd.exe
  ```

## Database Location

The database is stored at the absolute path given by `PWD_DB_FILE`. Ensure its directory exists and is writable by the application user before running the application.

## Development

Run in development mode:
```bash
go run .
```

Run tests:
```bash
go test ./...
```

## Deployment

The `deploy/` directory contains everything needed to deploy Gemini PWD to a Linux server running Apache2 as a reverse proxy, managed by systemd. See [deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md) for the full guide (SSL setup, backups, troubleshooting, etc.). The short version:

### 1. Build the deployment package

On your development machine:
```bash
chmod +x deploy/build-for-deployment.sh
./deploy/build-for-deployment.sh
```
This cross-compiles the Linux binary and bundles it with `templates/`, `static/`, and `create_base_db.sql` into `deploy/gemini-pwd-<timestamp>.tar.gz`.

### 2. Transfer it to the server

```bash
scp deploy/gemini-pwd-*.tar.gz user@your-server:/tmp/
```

### 3. Run `deploy.sh` on the server

`deploy.sh` expects the extracted package at `/tmp/gemini_pwd` and must be run as root:

```bash
cd /tmp
tar -xzf gemini-pwd-*.tar.gz
mv package gemini_pwd

# Run the deployment script (from wherever deploy.sh and its
# accompanying gemini_pwd.service / apache-gemini_pwd.conf files live,
# e.g. after also copying the deploy/ directory to the server)
chmod +x deploy.sh
sudo ./deploy.sh
```

`deploy.sh` installs Apache2/ufw/fail2ban, creates a dedicated `geminipwd` system user, copies the application into `/opt/gemini-pwd`, installs the systemd service and Apache vhost, enables the firewall, and starts the service. After it finishes, it prints follow-up steps (SSL certificates, domain name, backups) — see the "Deployment completed!" output or [deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md) for details.

Once deployed, manage the service with:
```bash
sudo systemctl start|stop|restart|status gemini_pwd
sudo journalctl -u gemini_pwd -f
```
