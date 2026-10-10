<!--
SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# OPEN-NVDEBUG

## Overview

NVDebug collects diagnostic data from NVIDIA server platforms. It supports
out-of-band collection from a BMC, in-band collection from a host, and combined
collection through Redfish, SSH, and IPMI.

Run NVDebug from Python source or build a native Linux executable locally.
Available collectors vary by platform. See `CONTRIBUTING.md` for build details.
See the [release notes](release-notes.txt) for the changes and upgrade guidance
for this version.

## Requirements

- A Linux amd64 or arm64 client with at least 4 GB RAM and sufficient free space
  for the expected support bundle
- Python 3.12 with its `venv` module, Node.js 24 with npm, and Make for setup and
  local builds
- Network access to the target BMC and/or host
- Valid BMC or host credentials for the requested collectors
- `ipmitool` and `sshpass` when the selected collection path requires them
- SSH access with the required privileges for host collection

Do not place real credentials in examples, tickets, or unprotected files. Prefer
the supported password environment variables or a protected DUT configuration.

## Install from source

Run these commands from the repository root. Select Python 3.12 explicitly when
creating the virtual environment; an existing environment may use a different
interpreter than your system default.

```shell
git clone https://github.com/NVIDIA/open-nvdebug.git
cd open-nvdebug
python3.12 -m venv .venv
. .venv/bin/activate
python --version
python -m pip install -r requirements.txt
python -m pip check
make build-report-app
```

`requirements.txt` installs the complete pinned Python runtime and binary-build
dependencies through `requirements-build.lock`. The report build installs its
JavaScript dependencies from `src/report-app/package-lock.json` and generates the
validated assets required for collection. Installation requires internet access.

### Run with Python

Keep the virtual environment active and run from the repository root:

```shell
python -m src.tool.main --version
python -m src.tool.main --help
python -m src.tool.main list-baseboards
python -m src.tool.main list-collectors
python -m src.tool.main collect --help
```

Use `--help` for help. Checking `list-baseboards` and `list-collectors` also verifies
CLI command dispatch and the included catalog; `--version` alone does not.
The `PYTHONPATH="$PWD/src" python -m tool.main` launch form is also supported.

### Build and run a binary

From the same environment and checkout, build for the current host architecture.
These examples use `amd64`; use `arm64` in the paths on an ARM64 host:

```shell
make build
./dist/amd64/nvdebug --version
./dist/amd64/nvdebug --help
./dist/amd64/nvdebug list-baseboards
./dist/amd64/nvdebug list-collectors
./dist/amd64/nvdebug collect --help
```

`dist/amd64/` or `dist/arm64/` contains the executable,
`config/Telemetry_Catalog_v*.xlsx`, editable `dut_config.yaml` and `tool_config.yaml`,
the README and build guide, release notes,
license notices, a versioned archive, and `SHA256SUMS`. The archive contains the
same executable, catalog, configuration, and documentation inside a versioned
directory. Run `sha256sum -c SHA256SUMS` from that architecture's output directory
to verify the loose files and archive. Builds for different architectures can
coexist under `dist/`.

The binary also embeds the catalog, default configuration, and validated report
assets. Build on each native architecture you need; the Linux/glibc baseline
follows the build host.
The resulting binary runs without Python, Node.js, or the source checkout.
Builds preserve an existing architecture output directory. For a subsequent build,
regenerate report assets and select a new output path:

```shell
make build-report-app
python -I scripts/build_binary.py --output /tmp/nvdebug-build-next
/tmp/nvdebug-build-next/nvdebug --version
```

## Collect data

The examples below use `nvdebug` on your `PATH`. From the checkout, use
`./dist/amd64/nvdebug` (or `./dist/arm64/nvdebug`) instead. For Python execution,
replace `nvdebug` with `python -m src.tool.main` while the virtual environment is
active. For example:

```shell
export NVDEBUG_BMC_PASSWORD='<BMC_PASSWORD>'
python -m src.tool.main collect -i <BMC_IP> -u <BMC_USER>
# Equivalent using the locally built executable:
./dist/amd64/nvdebug collect -i <BMC_IP> -u <BMC_USER>
```

Run an out-of-band collection:

```shell
export NVDEBUG_BMC_PASSWORD='<BMC_PASSWORD>'
nvdebug collect -i <BMC_IP> -u <BMC_USER>
```

Run a host collection:

```shell
export NVDEBUG_HOST_PASSWORD='<HOST_PASSWORD>'
nvdebug collect -I <HOST_IP> -U <HOST_USER>
```

Run combined BMC and host collection:

```shell
export NVDEBUG_BMC_PASSWORD='<BMC_PASSWORD>'
export NVDEBUG_HOST_PASSWORD='<HOST_PASSWORD>'
nvdebug collect -i <BMC_IP> -u <BMC_USER> \
  -I <HOST_IP> -U <HOST_USER>
```

Use a DUT configuration for repeatable or multi-DUT collection:

```shell
nvdebug collect --dut-config /path/to/dut_config.yaml
```

Use an Ansible inventory when that is the target definition supplied for the
system:

```shell
nvdebug collect --ansible-inventory /path/to/inventory.yaml
```

List supported choices before a collection:

```shell
nvdebug list-baseboards
nvdebug list-collectors --baseboard '<BASEBOARD>'
```

Limit a diagnostic run to specific collector IDs with `-S`:

```shell
nvdebug collect --dut-config /path/to/dut_config.yaml -S 'R1 R2 H4'
```

Add `-V` for L2 or `-VV` for L3 collection. Add `--debug` only when detailed
diagnostics are needed because verbose runs can produce substantially more data.

## Configuration

For Python source runs, start from `default_config/dut_config.yaml` and
`default_config/tool_config.yaml`. Binary builds place editable copies beside
`nvdebug`, with the Telemetry Catalog in `config/`. After extracting the binary
archive, run `./nvdebug` from its versioned directory. Use `--dut-config`,
`--tool-config`, or `--spreadsheet` to select a particular file explicitly.

Keep credentials empty in any file that may be shared and provide them through
the documented environment variables where practical. Relevant variables include:

- `NVDEBUG_BMC_PASSWORD`
- `NVDEBUG_BMC_SSH_PASSWORD`
- `NVDEBUG_BMC_REDFISH_PASSWORD`
- `NVDEBUG_HOST_PASSWORD`

Use `nvdebug COMMAND --help` for the options supported by the installed version.
Package help is the authoritative interface for that package.

## Output and reports

A collection creates a timestamped output directory and, unless disabled, one
or more archives. Important output includes:

```text
<output>/
├── .nvdebug_stdout.log
├── reports/
│   └── index.html
└── <dut_name>/
    ├── Execution_Summary_Report.txt
    ├── nvdebug_runtime_output.txt
    ├── nvdebug_runtime_output_structured.json
    ├── error_logs/
    ├── host/
    ├── ipmi/
    ├── redfish/
    └── ssh/
```

Open `reports/index.html` in a browser for the interactive report. Use
`Execution_Summary_Report.txt` for the per-collector result and the runtime logs
for detailed diagnostics.

The report application is generated by `make build-report-app` for source runs
and embedded by `make build` for binaries. If report assets are unavailable or
invalid, rebuild them using the command for your launch method before retrying.

## Troubleshooting

### Target is unreachable

- Confirm the target address and route from the client.
- Confirm that HTTPS/Redfish, SSH, or IPMI access is permitted for the selected
  collectors.
- Confirm that the BMC or host service is responsive before retrying.

### Authentication fails

- Confirm the account and password outside NVDebug through an approved access
  method.
- Confirm the account has the privileges required by the requested collectors.
- Avoid placing passwords directly on the command line or in shared output.

### Platform detection fails

List available baseboards and supply the correct value explicitly:

```shell
nvdebug list-baseboards
nvdebug collect --dut-config /path/to/dut_config.yaml --baseboard '<BASEBOARD>'
```

### A collector is skipped or fails

- A skipped collector can be normal when it does not apply to the platform.
- Review `Execution_Summary_Report.txt` and the corresponding `error_logs/`
  entry.
- Re-run only the necessary collector IDs with `-S` when a focused retry is
  appropriate.

### Collection is slow or large

- L3, system-dump, and highly verbose collectors can take significant time and
  disk space.
- Check available disk space and network stability.
- Use a focused `-S` run for diagnosis instead of repeating an entire long run.

## Support and contribution

- NVIDIA support: <https://support.nvidia.com>
- NVIDIA documentation: <https://docs.nvidia.com>
- NVIDIA developer forums: <https://forums.developer.nvidia.com>
- Source contribution guidance: `CONTRIBUTING.md`

Always include the output summary, NVDebug version, target platform, and the
smallest relevant sanitized logs when requesting support. Never attach secrets.
