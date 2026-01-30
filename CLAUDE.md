# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Gemini PWD is a secure password manager built with Go. It uses SQLite for storage, AES-256-GCM encryption for passwords, and includes user management with tagging features.

## Common Commands

### Build
```bash
# Development build
./build.sh local dev        # Linux/macOS
build.bat local dev         # Windows

# Release build (optimized, stripped)
./build.sh local release

# Cross-platform builds
./build.sh all release      # All platforms
./build.sh linux release    # Linux only
./build.sh windows release  # Windows only
```

### Test
```bash
go test ./...                           # All tests
go test -run TestName                   # Single test by name
go test -run TestPasswordsAPIHandler    # Example: handlers test
```

### Development
```bash
air                     # Live reload (uses .air.toml config)
go run .                # Manual run
```

### Direct Compilation (requires CGO)
```bash
CGO_ENABLED=1 go build -o gemini-pwd           # Linux/WSL
$env:CGO_ENABLED=1; go build -o gemini-pwd.exe # Windows PowerShell
wsl CGO_ENABLED=1 go build -o gemini-pwd       # Windows via WSL
```

## Architecture

### Root-level Core Files
- `main.go` - Server setup, route registration
- `handlers.go` - HTTP request handlers for all endpoints
- `auth.go` - Authentication, rate limiting, session management
- `database.go` - SQLite initialization, schema creation
- `encrypt.go` - AES-256-GCM encryption with PBKDF2 key derivation
- `user.go` - User CRUD operations
- `models.go` - Data structures

### Reusable Packages (pkg/)
- `pkg/api/` - Request decoding, response utilities
- `pkg/auth/` - Context-based user retrieval
- `pkg/httputil/` - JSON response writers
- `pkg/logger/` - Structured logging with emoji prefixes
- `pkg/template/` - HTML template rendering (with/without base layout)
- `pkg/validation/` - Chainable input validation

### Frontend
- `templates/` - HTML templates (base.html is the layout wrapper)
- `static/` - JavaScript utilities, favicon

## Key Patterns

### Database
- Global `var db *sql.DB` shared across all files
- SQLite with WAL mode, foreign keys enabled
- MaxOpenConns=1 (SQLite limitation)

### Authentication
- Middleware: `authMiddleware()` wraps protected routes
- User passed through request context with `userContextKey`
- Database-backed sessions with automatic expiry cleanup

### Security
- Rate limiting: 3 attempts/30sec, 6 attempts/5min per username
- bcrypt for user passwords, AES-256-GCM for stored passwords
- PBKDF2 key derivation with unique salt per password entry

### Validation
- Chainable validator: `.Required().MinLength(n).MaxLength(n)`
- Located in `pkg/validation/rules.go`

### Testing
- `0_test_init.go` - Sets PWD_SECRET_KEY (named to run first)
- `ensureTestDB()` - Cleans tables in dependency order before tests
- Helper: `newRequestWithUser()` for authenticated request testing

## Required Environment

- `PWD_SECRET_KEY` - **Required**, exactly 32 bytes for AES-256. Fatal error if missing.
- `PORT` - Optional, defaults to 7000

## Default Credentials

- Username: `super`
- Password: `abcd1234`

## CGO Requirement

SQLite driver requires CGO. Without a C compiler, use WSL on Windows.
