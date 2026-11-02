#!/bin/bash
# Copyright (C) 2025 Joshua Goldstein

# Gemini PWD Deployment Script
# Run this script as root or with sudo.
#
# Usage:
#   sudo ./deploy.sh [PACKAGE_DIR]
#
#   PACKAGE_DIR   Directory holding gemini-pwd, templates/ and static/
#                 (default: this script's directory, i.e. the extracted package)
#
# Run it from anywhere; gemini_pwd.service and apache-gemini_pwd.conf are read
# from the same directory as this script. build-for-deployment.sh puts all of
# these in one package, so normally: sudo /tmp/gemini_pwd/deploy.sh
#
# Required configuration (first deployment only):
#   PWD_DB_FILE     Absolute path to the SQLite database file
#   PWD_SECRET_KEY  Exactly 32-byte encryption key
# If they are not set in the environment the script prompts for them (the key
# is read without echo). They are written to $ENV_FILE (root-only, mode 600),
# which the service loads via a systemd drop-in. If $ENV_FILE already exists it
# is left untouched, so re-running this script never replaces an existing key.

set -euo pipefail

echo "=== Gemini PWD Deployment Script ==="

# Configuration
SERVICE_NAME="gemini_pwd"
APP_BINARY="gemini-pwd"
APP_USER="geminipwd"
APP_DIR="/opt/gemini-pwd"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE_DROPIN_DIR="/etc/systemd/system/${SERVICE_NAME}.service.d"
SERVICE_DROPIN_FILE="${SERVICE_DROPIN_DIR}/deploy.conf"
ENV_FILE="/etc/${SERVICE_NAME}.env"
APACHE_SITE_NAME="gemini_pwd"
APACHE_SITE_FILE="/etc/apache2/sites-available/${APACHE_SITE_NAME}.conf"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="${1:-$SCRIPT_DIR}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

die() {
    print_error "$1"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   die "This script must be run as root or with sudo"
fi

# Pre-flight: make sure everything we need is present before changing the system
[ -f "$PACKAGE_DIR/$APP_BINARY" ] || die "Application binary not found at $PACKAGE_DIR/$APP_BINARY (pass the extracted package directory as the first argument)"
[ -d "$PACKAGE_DIR/templates" ]   || die "templates/ not found in $PACKAGE_DIR"
[ -d "$PACKAGE_DIR/static" ]      || die "static/ not found in $PACKAGE_DIR"
[ -f "$SCRIPT_DIR/gemini_pwd.service" ]      || die "gemini_pwd.service not found next to deploy.sh ($SCRIPT_DIR)"
[ -f "$SCRIPT_DIR/apache-gemini_pwd.conf" ]  || die "apache-gemini_pwd.conf not found next to deploy.sh ($SCRIPT_DIR)"

# Pre-flight: collect and validate the runtime configuration
if [ -f "$ENV_FILE" ]; then
    print_warning "$ENV_FILE already exists; keeping its PWD_SECRET_KEY and PWD_DB_FILE"
    PWD_DB_FILE="$(sed -n "s/^PWD_DB_FILE=//p" "$ENV_FILE" | tail -n 1 | sed "s/^'\(.*\)'$/\1/")"
    [ -n "$PWD_DB_FILE" ] || die "PWD_DB_FILE is not set in $ENV_FILE"
    WRITE_ENV_FILE=0
else
    if [ -z "${PWD_DB_FILE:-}" ]; then
        read -r -p "Absolute path to the database file (PWD_DB_FILE): " PWD_DB_FILE
    fi
    if [ -z "${PWD_SECRET_KEY:-}" ]; then
        read -r -s -p "32-byte encryption key (PWD_SECRET_KEY, input hidden): " PWD_SECRET_KEY
        echo
    fi
    key_len=$(printf '%s' "$PWD_SECRET_KEY" | wc -c)
    [ "$key_len" -eq 32 ] || die "PWD_SECRET_KEY must be exactly 32 bytes (got $key_len)"
    case "$PWD_SECRET_KEY" in
        *\'*|*\\*) die "PWD_SECRET_KEY must not contain single quotes or backslashes" ;;
    esac
    WRITE_ENV_FILE=1
fi
[[ "$PWD_DB_FILE" == /* ]] || die "PWD_DB_FILE must be an absolute path (got '$PWD_DB_FILE')"
case "$PWD_DB_FILE" in
    *\'*|*\\*|*[[:space:]]*) die "PWD_DB_FILE must not contain quotes, backslashes or whitespace" ;;
esac
DB_DIR="$(dirname "$PWD_DB_FILE")"

print_status "Starting deployment..."
print_status "Package:  $PACKAGE_DIR"
print_status "Database: $PWD_DB_FILE"

# 1. Update system packages
print_status "Updating system packages..."
apt update && apt upgrade -y

# 2. Install required packages
print_status "Installing required packages..."
apt install -y apache2 ufw fail2ban

# 3. Enable required Apache modules
print_status "Enabling Apache modules..."
a2enmod ssl
a2enmod proxy
a2enmod proxy_http
a2enmod headers
a2enmod deflate
a2enmod rewrite

# 4. Create application user
print_status "Creating application user..."
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --shell /bin/false --home-dir "$APP_DIR" --create-home "$APP_USER"
    print_status "Created user: $APP_USER"
else
    print_warning "User $APP_USER already exists"
fi

# 5. Create application directory
print_status "Setting up application directory..."
mkdir -p "$APP_DIR"
chown "$APP_USER:$APP_USER" "$APP_DIR"
chmod 755 "$APP_DIR"

# 6. Set up the database directory
#    Only take ownership of a directory we create; an existing directory must
#    already be writable by the app user (we never chown an existing tree).
print_status "Setting up database directory $DB_DIR..."
if [ ! -d "$DB_DIR" ]; then
    mkdir -p "$DB_DIR"
    chown "$APP_USER:$APP_USER" "$DB_DIR"
    chmod 700 "$DB_DIR"
    print_status "Created $DB_DIR (owner $APP_USER, mode 700)"
elif ! runuser -u "$APP_USER" -- test -w "$DB_DIR"; then
    die "$DB_DIR exists but is not writable by $APP_USER; fix its ownership/permissions and re-run"
fi
if [ -e "$PWD_DB_FILE" ] && ! runuser -u "$APP_USER" -- test -w "$PWD_DB_FILE"; then
    die "$PWD_DB_FILE exists but is not writable by $APP_USER; fix its ownership/permissions and re-run"
fi

# 7. Write the environment file (secrets; root-only)
if [ "$WRITE_ENV_FILE" -eq 1 ]; then
    print_status "Writing $ENV_FILE..."
    (
        umask 077
        cat > "$ENV_FILE" << EOF
# Gemini PWD runtime configuration (loaded by systemd; keep mode 600, owner root)
# WARNING: if PWD_SECRET_KEY is lost, all stored passwords are unrecoverable. Back it up.
PWD_SECRET_KEY='${PWD_SECRET_KEY}'
PWD_DB_FILE='${PWD_DB_FILE}'
EOF
    )
    chown root:root "$ENV_FILE"
    chmod 600 "$ENV_FILE"
fi
unset PWD_SECRET_KEY

# 8. Stop the service if it is already running (a running binary can't be overwritten)
if systemctl is-active --quiet "$SERVICE_NAME"; then
    print_status "Stopping running $SERVICE_NAME service..."
    systemctl stop "$SERVICE_NAME"
fi

# 9. Copy application files
print_status "Copying application files from $PACKAGE_DIR..."
rm -rf "$APP_DIR/templates" "$APP_DIR/static"
cp "$PACKAGE_DIR/$APP_BINARY" "$APP_DIR/"
cp -r "$PACKAGE_DIR/templates" "$PACKAGE_DIR/static" "$APP_DIR/"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod 755 "$APP_DIR/$APP_BINARY"
# Directories traversable, files read-only
find "$APP_DIR/templates" "$APP_DIR/static" -type d -exec chmod 755 {} +
find "$APP_DIR/templates" "$APP_DIR/static" -type f -exec chmod 644 {} +

# 10. Install systemd service
print_status "Installing systemd service..."
cp "$SCRIPT_DIR/gemini_pwd.service" "$SERVICE_FILE"
mkdir -p "$SERVICE_DROPIN_DIR"
cat > "$SERVICE_DROPIN_FILE" << EOF
# Generated by deploy.sh
[Service]
EnvironmentFile=$ENV_FILE
# ProtectSystem=strict makes the filesystem read-only; allow the database directory
ReadWritePaths=$DB_DIR
EOF
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
print_status "Service installed and enabled"

# 11. Configure Apache
print_status "Configuring Apache..."
cp "$SCRIPT_DIR/apache-gemini_pwd.conf" "$APACHE_SITE_FILE"
a2dissite 000-default || true
a2ensite "$APACHE_SITE_NAME"
print_status "Apache configured"

# 12. Configure firewall (allow SSH *before* enabling so we don't cut ourselves off)
print_status "Configuring firewall..."
ufw allow ssh
ufw allow 'Apache Full'
ufw --force enable
ufw reload

# 13. Configure fail2ban
print_status "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true

[apache-auth]
enabled = true

[apache-badbots]
enabled = true

[apache-noscript]
enabled = true

[apache-overflows]
enabled = true
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# 14. Start services
print_status "Starting services..."
systemctl start "$SERVICE_NAME"
APACHE_OK=1
if apache2ctl configtest; then
    systemctl reload apache2
else
    APACHE_OK=0
    print_warning "Apache config test failed (expected until the domain name and SSL certificate paths"
    print_warning "in $APACHE_SITE_FILE are filled in). Fix it, then run: systemctl reload apache2"
fi

# 15. Check service status
print_status "Checking service status..."
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    print_status "Gemini PWD service is running"
else
    print_error "Gemini PWD service failed to start; see: journalctl -u $SERVICE_NAME -n 50"
fi
systemctl is-active --quiet apache2 && print_status "Apache2 service is running" || print_error "Apache2 service is not running"

print_status "Deployment completed!"
print_warning "Don't forget to:"
if [ "$APACHE_OK" -eq 0 ]; then
    print_warning "*. Fix the Apache configuration (see warning above)"
fi
print_warning "1. Configure SSL certificates (Let's Encrypt recommended)"
print_warning "2. Update the domain name in Apache configuration"
print_warning "3. Review and adjust firewall rules as needed"
print_warning "4. Set up regular backups of $PWD_DB_FILE and keep a safe copy of $ENV_FILE (the encryption key)"
print_warning "5. Monitor logs: journalctl -u $SERVICE_NAME -f"

echo ""
print_status "Service management commands:"
echo "  Start:   sudo systemctl start $SERVICE_NAME"
echo "  Stop:    sudo systemctl stop $SERVICE_NAME"
echo "  Restart: sudo systemctl restart $SERVICE_NAME"
echo "  Status:  sudo systemctl status $SERVICE_NAME"
echo "  Logs:    sudo journalctl -u $SERVICE_NAME -f"
