#!/bin/bash

# Build script for gemini_pwd deployment
# This script builds the application for Linux deployment

set -e

echo "=== Building Gemini PWD for Deployment ==="

# Check if we're in the right directory
if [ ! -f "main.go" ]; then
    echo "Error: main.go not found. Please run this script from the project root."
    exit 1
fi

# Create deployment directory
mkdir -p deploy/package

# Build for Linux (assuming deployment on Ubuntu/Debian)
echo "Building for Linux amd64..."
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o deploy/package/gemini_pwd .

# Copy required files
echo "Copying application files..."
cp -r templates deploy/package/
cp -r static deploy/package/
cp create_base_db.sql deploy/package/
cp README.md deploy/package/

# Create a deployment package
echo "Creating deployment package..."
cd deploy
tar -czf gemini_pwd-$(date +%Y%m%d-%H%M%S).tar.gz package/

echo "Build completed!"
echo "Deployment package created in deploy/ directory"
echo ""
echo "To deploy:"
echo "1. Copy the tar.gz file to your server"
echo "2. Extract it: tar -xzf gemini_pwd-*.tar.gz"
echo "3. Move contents to /tmp/gemini_pwd/"
echo "4. Run the deployment script as root"
