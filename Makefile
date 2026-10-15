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

PYTHON ?= python3.12
.DEFAULT_GOAL := help
.PHONY: help setup install build build-report-app test-report-app lint-report-app audit-report-app report-app-ci
# These targets share node_modules and generated report assets.
.NOTPARALLEL:

help:
	@echo 'setup            Create .venv and install pinned public build dependencies'
	@echo 'install          Build report assets and install the nvdebug Python command'
	@echo 'build            Build report assets and a native Linux package in dist/<arch>/'
	@echo 'build-report-app Build validated report assets for running from source'
	@echo 'audit-report-app Check locked report dependencies for known vulnerabilities'
	@echo 'report-app-ci    Audit, lint, test, and build the report application'

setup:
	$(PYTHON) -m venv .venv
	.venv/bin/python -m pip install --require-hashes -r requirements.txt

build: build-report-app
	$(PYTHON) -I scripts/build_binary.py

install: build-report-app
	$(PYTHON) -m pip install --no-build-isolation .

build-report-app:
	@bash scripts/build_report_app.sh

test-report-app:
	@cd src/report-app && npm ci && npm run test

lint-report-app:
	@cd src/report-app && npm ci && npm run lint

audit-report-app:
	@cd src/report-app && npm ci && npm audit

report-app-ci: audit-report-app lint-report-app test-report-app build-report-app
