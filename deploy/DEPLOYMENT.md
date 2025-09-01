# Password Manager Deployment Guide

This guide will help you deploy the Password Manager application to a Linux server using Apache2 as a reverse proxy and systemd for service management.

## Prerequisites

- Ubuntu/Debian Linux server
- Root or sudo access
- Domain name pointing to your server (recommended)
- Basic knowledge of Linux administration

## Files Overview

The deployment package includes:

- `password-manager` - The compiled Go binary
- `templates/` - HTML templates directory
- `create_base_db.sql` - Database initialization script
- `password-manager.service` - Systemd service configuration
- `apache-password-manager.conf` - Apache virtual host configuration
- `deploy.sh` - Automated deployment script

## Quick Deployment

### Step 1: Build the Application

On your development machine (Windows):

```bash
# Make the build script executable and run it
chmod +x deploy/build-for-deployment.sh
./deploy/build-for-deployment.sh
```

This creates a deployment package in the `deploy/` directory.

### Step 2: Transfer to Server

Copy the generated tar.gz file to your server:

```bash
# Example using scp
scp deploy/password-manager-*.tar.gz user@your-server:/tmp/
```

### Step 3: Deploy on Server

On your Linux server:

```bash
# Extract the deployment package
cd /tmp
tar -xzf password-manager-*.tar.gz
mv package password-manager

# Run the deployment script
cd /path/to/deploy/files
chmod +x deploy.sh
sudo ./deploy.sh
```

## Manual Deployment

If you prefer manual deployment:

### 1. Install Dependencies

```bash
sudo apt update
sudo apt install -y apache2 ufw fail2ban
```

### 2. Enable Apache Modules

```bash
sudo a2enmod ssl proxy proxy_http headers deflate rewrite
```

### 3. Create Application User

```bash
sudo useradd --system --shell /bin/false --home-dir /opt/password-manager --create-home passwordmgr
```

### 4. Install Application

```bash
# Create directory and copy files
sudo mkdir -p /opt/password-manager
sudo cp password-manager /opt/password-manager/
sudo cp -r templates /opt/password-manager/
sudo cp create_base_db.sql /opt/password-manager/

# Set permissions
sudo chown -R passwordmgr:passwordmgr /opt/password-manager
sudo chmod +x /opt/password-manager/password-manager
```

### 5. Install Systemd Service

```bash
sudo cp password-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable password-manager
sudo systemctl start password-manager
```

### 6. Configure Apache

```bash
# Copy Apache configuration
sudo cp apache-password-manager.conf /etc/apache2/sites-available/password-manager.conf

# Edit the configuration to update your domain name
sudo nano /etc/apache2/sites-available/password-manager.conf

# Enable the site
sudo a2dissite 000-default
sudo a2ensite password-manager
sudo systemctl reload apache2
```

### 7. Configure Firewall

```bash
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 'Apache Full'
```

## SSL Certificate Setup

### Using Let's Encrypt (Recommended)

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-apache

# Get certificate (replace with your domain)
sudo certbot --apache -d your-domain.com -d www.your-domain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

### Using Custom Certificates

Edit `/etc/apache2/sites-available/password-manager.conf` and update the SSL certificate paths:

```apache
SSLCertificateFile /path/to/your/certificate.crt
SSLCertificateKeyFile /path/to/your/private.key
```

## Configuration

### Application Configuration

The application uses environment variables:

- `PORT` - Port to run on (default: 8081 for deployment)
- `GIN_MODE` - Set to "release" for production

These are set in the systemd service file.

### Database

The application will automatically create `passwords.db` in the application directory on first run.

### Security Features

The deployment includes:

- **Firewall**: UFW with restricted access
- **Fail2ban**: Protection against brute force attacks  
- **HTTPS**: SSL/TLS encryption
- **Security Headers**: XSS protection, HSTS, etc.
- **Reverse Proxy**: Apache handles SSL termination

## Service Management

```bash
# Start the service
sudo systemctl start password-manager

# Stop the service
sudo systemctl stop password-manager

# Restart the service
sudo systemctl restart password-manager

# Check status
sudo systemctl status password-manager

# View logs
sudo journalctl -u password-manager -f

# View Apache logs
sudo tail -f /var/log/apache2/password-manager_error.log
sudo tail -f /var/log/apache2/password-manager_access.log
```

## Backup Strategy

### Database Backup

```bash
# Create backup script
sudo nano /opt/password-manager/backup.sh

#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/password-manager/backups"
mkdir -p "$BACKUP_DIR"
cp /opt/password-manager/passwords.db "$BACKUP_DIR/passwords_$DATE.db"
find "$BACKUP_DIR" -name "passwords_*.db" -mtime +30 -delete

# Make executable and add to cron
sudo chmod +x /opt/password-manager/backup.sh
sudo crontab -e
# Add: 0 2 * * * /opt/password-manager/backup.sh
```

## Troubleshooting

### Service Won't Start

```bash
# Check service status and logs
sudo systemctl status password-manager
sudo journalctl -u password-manager -n 50

# Common issues:
# - Port already in use
# - Permission problems
# - Missing files
```

### Apache Issues

```bash
# Check Apache configuration
sudo apache2ctl configtest

# Check Apache status
sudo systemctl status apache2

# Check error logs
sudo tail -f /var/log/apache2/error.log
```

### Database Issues

```bash
# Check database permissions
ls -la /opt/password-manager/passwords.db

# Ensure the passwordmgr user can read/write
sudo chown passwordmgr:passwordmgr /opt/password-manager/passwords.db
```

## Monitoring

### Log Monitoring

```bash
# Real-time application logs
sudo journalctl -u password-manager -f

# Real-time Apache logs
sudo tail -f /var/log/apache2/password-manager_access.log
```

### Performance Monitoring

Consider installing monitoring tools like:

- **htop** - Process monitoring
- **iotop** - Disk I/O monitoring  
- **netstat** - Network connections
- **logwatch** - Log analysis

## Security Considerations

1. **Regular Updates**: Keep the system and packages updated
2. **Strong Passwords**: Use strong passwords for all accounts
3. **SSH Keys**: Use SSH key authentication instead of passwords
4. **Fail2ban**: Monitor and adjust fail2ban rules
5. **Backups**: Implement automated, tested backup procedures
6. **Monitoring**: Set up log monitoring and alerting
7. **Network**: Consider using a VPN or restricting access by IP

## Updating the Application

1. Build new version using `build-for-deployment.sh`
2. Stop the service: `sudo systemctl stop password-manager`
3. Backup the database: `cp /opt/password-manager/passwords.db /tmp/`
4. Replace the binary: `sudo cp password-manager /opt/password-manager/`
5. Update templates if needed: `sudo cp -r templates /opt/password-manager/`
6. Set permissions: `sudo chown passwordmgr:passwordmgr /opt/password-manager/password-manager`
7. Start the service: `sudo systemctl start password-manager`
