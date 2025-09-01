# Password Manager

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
wsl CGO_ENABLED=1 go build -o gemini_pwd
```

### Manual Build Commands

**Linux/WSL:**
```bash
CGO_ENABLED=1 go build -o gemini_pwd
```

**Windows with C compiler:**
```powershell
$env:CGO_ENABLED=1; go build -o gemini_pwd.exe
```

**Windows without C compiler (use WSL):**
```powershell
wsl CGO_ENABLED=1 go build -o gemini_pwd
```

### Running

**Linux/WSL:**
```bash
./gemini_pwd
```

**Windows (if native build succeeded):**
```cmd
gemini_pwd.exe
```

**Windows via WSL (recommended):**
```powershell
wsl ./gemini_pwd
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

3. Run the application:
   ```bash
   ./gemini_pwd      # Linux/WSL
   gemini_pwd.exe    # Windows
   ```

4. Open your browser to `http://localhost:8080`

## Default Credentials

- Username: `super`
- Password: `abcd1234`

**⚠️ IMPORTANT: Change the default password immediately after first login!**

## Rate Limiting

- **3 failed attempts**: 30-second cooldown
- **6+ failed attempts**: 5-minute cooldown

## Environment Variables

- `PWD_SECRET_KEY`: 32-byte encryption key (defaults to a hardcoded key - **change in production!**)

## Development

Run in development mode:
```bash
go run .
```

Run tests:
```bash
go test ./...
```
