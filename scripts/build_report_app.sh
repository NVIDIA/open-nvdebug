#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_APP_DIR="$PROJECT_DIR/src/report-app"
DIST_DIR="$PROJECT_DIR/src/tool/report_app_dist"

echo "Building report app..."
cd "$REPORT_APP_DIR"

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm ci ${REPORT_APP_NPM_CI_FLAGS}
fi

# Build
echo "Running production build..."
npm run build

# Copy to dist location
echo "Copying build output to $DIST_DIR..."
rm -rf "$DIST_DIR"
cp -r dist/ "$DIST_DIR"
touch "$DIST_DIR/.gitkeep"

echo "Done! Report app built and copied to src/tool/report_app_dist/"
ls -la "$DIST_DIR"
