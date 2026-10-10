#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_APP_DIR="$PROJECT_DIR/src/report-app"
DIST_DIR="$PROJECT_DIR/src/tool/report_app_dist"

echo "Building report app..."
cd "$REPORT_APP_DIR"

# Re-materialize dependencies from the reviewed lock on every build. Reusing
# ambient node_modules would let unverified bytes enter the frozen report app.
echo "Installing dependencies from package-lock.json..."
npm ci

# Build
echo "Running production build..."
npm run build

# Copy to dist location
echo "Copying build output to $DIST_DIR..."
rm -rf "$DIST_DIR"
cp -r dist/ "$DIST_DIR"
touch "$DIST_DIR/.gitkeep"
python3 -I "$PROJECT_DIR/scripts/generate_report_app_dist_manifest.py" \
    "$REPORT_APP_DIR" "$DIST_DIR"

echo "Done! Report app built and copied to src/tool/report_app_dist/"
ls -la "$DIST_DIR"
