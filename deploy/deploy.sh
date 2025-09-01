#!/bin/bash

# Gemini PWD Deployment Script
# Run this script as root or with sudo

set -e

echo "=== Gemini PWD Deployment Script ==="

# Configuration
APP_NAME="gemini_pwd"
APP_USER="geminipwd"
APP_DIR="/opt/gemini_pwd"
SERVICE_FILE="/etc/systemd/system/gemini_pwd.service"
APACHE_SITE_FILE="/etc/apache2/sites-available/gemini_pwd.conf"

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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root or with sudo"
   exit 1
fi

print_status "Starting deployment..."

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

# Ensure the parent directory (/opt) is writable for database
chown "$APP_USER:$APP_USER" /opt

# 6. Copy application files (assumes you've already copied them to /tmp/gemini_pwd)
if [ -d "/tmp/gemini_pwd" ]; then
    print_status "Copying application files..."
    cp -r /tmp/gemini_pwd/* "$APP_DIR/"
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    chmod +x "$APP_DIR/gemini_pwd"
    # Ensure static files have correct permissions
    if [ -d "$APP_DIR/static" ]; then
        chmod -R 644 "$APP_DIR/static"
        chmod 755 "$APP_DIR/static"
    fi
else
    print_warning "Application files not found in /tmp/gemini_pwd"
    print_warning "Please copy your application files to $APP_DIR manually"
fi

# 7. Install systemd service
print_status "Installing systemd service..."
if [ -f "gemini_pwd.service" ]; then
    cp gemini_pwd.service "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable gemini_pwd
    print_status "Service installed and enabled"
else
    print_error "Service file not found!"
fi

# 8. Configure Apache
print_status "Configuring Apache..."
if [ -f "apache-gemini_pwd.conf" ]; then
    cp apache-gemini_pwd.conf "$APACHE_SITE_FILE"
    
    # Disable default site and enable our site
    a2dissite 000-default
    a2ensite gemini_pwd
    
    print_status "Apache configured"
else
    print_error "Apache configuration file not found!"
fi

# 9. Configure firewall
print_status "Configuring firewall..."
ufw --force enable
ufw allow ssh
ufw allow 'Apache Full'
ufw reload

# 10. Configure fail2ban
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

# 11. Start services
print_status "Starting services..."
systemctl start gemini_pwd
systemctl reload apache2

# 12. Check service status
print_status "Checking service status..."
systemctl is-active --quiet gemini_pwd && print_status "Gemini PWD service is running" || print_error "Gemini PWD service failed to start"
systemctl is-active --quiet apache2 && print_status "Apache2 service is running" || print_error "Apache2 service failed to start"

print_status "Deployment completed!"
print_warning "Don't forget to:"
print_warning "1. Configure SSL certificates (Let's Encrypt recommended)"
print_warning "2. Update the domain name in Apache configuration"
print_warning "3. Review and adjust firewall rules as needed"
print_warning "4. Set up regular backups for the database"
print_warning "5. Monitor logs: journalctl -u gemini_pwd -f"

echo ""
print_status "Service management commands:"
echo "  Start:   sudo systemctl start gemini_pwd"
echo "  Stop:    sudo systemctl stop gemini_pwd"
echo "  Restart: sudo systemctl restart gemini_pwd"
echo "  Status:  sudo systemctl status gemini_pwd"
echo "  Logs:    sudo journalctl -u gemini_pwd -f"
