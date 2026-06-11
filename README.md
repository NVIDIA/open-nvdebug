# OPEN-NVDEBUG

> SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
>
> SPDX-License-Identifier: Apache-2.0

## Description
**open-nvdebug** is NVIDIA's comprehensive diagnostic collection tool that gathers system information from NVIDIA server platforms to troubleshoot issues effectively. It collects data through multiple methods including Out-of-Band (OOB) access via BMC and In-Band (IB) access via host systems using Redfish, SSH, and IPMI protocols.

## Features
- **Comprehensive Data Collection**: Gathers logs from multiple sources in a single command
    - **Out-of-Band (OOB)**: Remote collection via BMC using Redfish and IPMI
    - **In-Band (IB)**: Direct collection from host operating system via SSH
    - **Combined Mode**: Simultaneous OOB and IB collection for complete diagnostics
- **Multi-Protocol Support**:
    - **Redfish API**: BMC log collection via Redfish interface
    - **SSH**: Direct SSH access to BMC and host systems
    - **IPMI**: IPMI-over-LAN for BMC communication
- **Broad Platform Support**: Supports NVIDIA HGX™, MGX™, GB series, GH series, and Workstation platforms
- **Automated Platform Detection**: Automatically detects baseboard type and platform architecture
- **Remote & Local Operation**: Works from remote machines or directly on the target system
- **Standardized Output**: Generates structured logs with HTML reports for easy analysis
- **Parallel Collection**: Optimized multi-threaded collection for faster performance
- **Configurable Collectors**: Spreadsheet-driven collector definitions for easy customization

## Prerequisites

Before you begin, ensure you have met the following requirements:

### Client Host Requirements
- **Operating System**: Linux-based OS (Ubuntu 24.04 recommended, Ubuntu 20.04+ supported)
- **Kernel**: Linux Kernel 4.4 or later (4.15+ recommended)
- **Python**: Python 3.12 (required)
- **Required Packages**:
```shell
sudo apt-get install ipmitool sshpass
```
- **Hardware**: Minimum 4GB RAM, 2GB free disk space
- **Network**: Access to target systems via BMC (Redfish/IPMI) and SSH

### Server/BMC Requirements
For full functionality, target systems should have:
- BMC accessible via Redfish, SSH, and IPMI-over-LAN
- For host collection: SSH access to host OS with sudo privileges
- For advanced collectors: Additional tools installed (nvme-cli, pciutils, dmidecode, lshw, nvidia-fabricmanager, mft-tools, NVIDIA Graphics Driver, doca-sosreport v4.8.0+, etc.)

## Quick Start

Get started with nvdebug in 5 minutes:

### Step 1: Verify Installation

```shell
python -m src.tool.main --version
```

### Step 2: Run Your First Collection

**Out-of-Band Collection (OOB)**

Collect logs remotely via BMC without host OS access:

```shell
python -m src.tool.main collect -i <BMC_IP> -u <BMC_USER> -p <BMC_PASS>
```

**In-Band Collection (IB)**

Collect logs directly from the host OS:

```shell
python -m src.tool.main collect -I <HOST_IP> -U <HOST_USER> -H <HOST_PASS>
```

**Combined OOB + IB Collection**

Collect both BMC and host logs:

```shell
python -m src.tool.main collect -i <BMC_IP> -u <BMC_USER> -p <BMC_PASS> \
                   -I <HOST_IP> -U <HOST_USER> -H <HOST_PASS>
```

### Step 3: Specify Baseboard (Optional)

nvdebug automatically detects your baseboard, but you can specify it manually:

```shell
# List available baseboards
python -m src.tool.main list-baseboards

# Collect with specific baseboard
python -m src.tool.main collect -i <BMC_IP> -u <BMC_USER> -p <BMC_PASS> -b "<baseboard>"
```

### Example Collection

```shell
# ARM64 system (<baseboard>) with auto-detection
python -m src.tool.main collect -i 192.168.1.100 -u admin -p password123

# With verbose output for detailed progress
python -m src.tool.main collect -i 192.168.1.100 -u admin -p password123 -v

# With custom output directory
python -m src.tool.main collect -i 192.168.1.100 -u admin -p password123 -o /tmp/my_logs

# Combined OOB and IB collection for <baseboard>
python -m src.tool.main collect -i 192.168.1.100 -u bmc_user -p bmc_pass \
                   -I 192.168.1.101 -U host_user -H host_pass \
                   -b "<baseboard>" -o /tmp/nvdebug_output
```

## Advanced Usage

### Local Mode

Run nvdebug directly on the target system:

```shell
# With BMC access
python -m src.tool.main collect -i <BMC_IP> -u <BMC_USER> -p <BMC_PASS> --local

# Without BMC access (host-only collection)
python -m src.tool.main collect --local
```

### Preflight Checks

Run preflight checks to verify system readiness before collection:

```shell
python -m src.tool.main preflight -i <BMC_IP> -u <BMC_USER> -p <BMC_PASS>
```

### List Available Resources

```shell
# List all supported baseboards
python -m src.tool.main list-baseboards

# List all available collectors
python -m src.tool.main list-collectors

# List collectors for specific baseboard
python -m src.tool.main list-collectors -b "<baseboard>"
```

### Configuration File Usage

Create a DUT configuration file (`dut_config.yaml`) for repeated collections:

```yaml
duts:
  - name: <baseboard>-node-01
    bmc_ip: 192.168.1.100
    bmc_user: admin
    bmc_pass: password123
    host_ip: 192.168.1.101
    host_user: host_user
    host_pass: host_password
    baseboard: "<baseboard>"
```

Run collection using configuration file:

```shell
python -m src.tool.main collect --dut-config dut_config.yaml
```

### Collection Options

```shell
# Verbose output for detailed progress
python -m src.tool.main collect -i <BMC_IP> -u <USER> -p <PASS> -v

# Very verbose output for debugging
python -m src.tool.main collect -i <BMC_IP> -u <USER> -p <PASS> -vv

# Specify custom output directory
python -m src.tool.main collect -i <BMC_IP> -u <USER> -p <PASS> -o /custom/path

# Specify baseboard manually (skip auto-detection)
python -m src.tool.main collect -i <BMC_IP> -u <USER> -p <PASS> -b "<baseboard>"
```

## Understanding Output

After running nvdebug, you'll find a timestamped directory containing all collected data:

```
nvdebug_logs_<date>_<time>/
├── .log_signature.txt                      # Log integrity verification
├── .nvdebug_stdout.log                     # nvdebug console output
├── reports/                                # HTML reports
│   ├── index.html                          # Main summary report
│   ├── file_map.html                       # File organization map
│   ├── status_complete.html                # Successfully collected data
│   ├── status_error.html                   # Failed collectors
│   ├── status_partial.html                 # Partially collected data
│   └── status_skipped.html                 # Skipped collectors
└── <dut_name>/                             # Per-device collection
    ├── config.json                         # Tool configuration used
    ├── dut_config.json                     # Device configuration
    ├── Execution_Summary_Report.txt        # Collection status summary
    ├── nvdebug_runtime_output.txt          # Detailed runtime logs
    ├── nvdebug_runtime_output_structured.json  # Structured logs
    ├── .metadata/                          # Collection metadata (JSON)
    ├── error_logs/                         # Error details for failed collectors
    ├── healthcheck/                        # System health check data
    ├── host/                               # Host-collected data
    ├── ipmi/                               # IPMI-collected data
    ├── redfish/                            # Redfish API data
    │   └── ...
    └── ssh/                                # BMC SSH-collected data
        └── ...
```

### Key Output Files

**Root Level:**
- `.log_signature.txt` - Verification signature for log integrity
- `.nvdebug_stdout.log` - Complete console output from nvdebug

**DUT Directory Files:**
- `Execution_Summary_Report.txt` - **Most important file**: Shows status of all collectors
- `nvdebug_runtime_output.txt` - Detailed execution logs with timestamps
- `nvdebug_runtime_output_structured.json` - Machine-readable execution data
- `config.json` - Configuration parameters used for this collection
- `dut_config.json` - Device-specific configuration details

**HTML Reports:**
- `reports/index.html` - **Open this first**: Visual summary of collection results
- `reports/file_map.html` - Browse collected files by category
- `reports/status_*.html` - Filter results by collection status

### Collector Naming Convention

Collectors are organized by type and numbered:
- **R1, R2, R3...** - Redfish collectors (e.g., `Redfish_R1_<collector_name>`)
- **S1, S2, S3...** - SSH collectors (e.g., `SSH_S2_<collector_name>`)
- **H1, H2, H3...** - Host collectors (e.g., `Host_H6_<collector_name>`)
- **I1, I2, I3...** - IPMI collectors (e.g., `IPMI_I1_<collector_name>`)

### SPA Report App

The default report format in v2.1.0 is the Vue SPA report. The Python collector writes a `manifest.json` for the run, copies the prebuilt SPA bundle from `src/tool/report_app_dist/` into `reports/`, and embeds the manifest into `reports/index.html`.

For source checkouts, build the SPA bundle before running collections:

```shell
make build-report-app
```

This runs `npm ci` and `npm run build` in `src/report-app`, then copies the single-file Vite build into `src/tool/report_app_dist/`. If the SPA bundle is not built, use the legacy report path explicitly:

```shell
python -m src.tool.main collect --report-format legacy ...
```

### Viewing Results

**HTML Reports (Recommended):**
```shell
cd nvdebug_logs_<date>_<time>
firefox reports/index.html  # or your preferred browser
```

**Text Summary:**
```shell
cd nvdebug_logs_<date>_<time>/<dut_name>
cat Execution_Summary_Report.txt
```

**Example Summary Output:**
```
Collection Name                    Execution Status    Log Path
═══════════════════════════════════════════════════════════════════════════════
<collector_name>                   Complete            /redfish/Redfish_R1_<collector_name>/
<collector_name>                   Complete            /ssh/SSH_S2_<collector_name>/SSH_S2_<collector_name>.txt
<collector_name>                   Complete            /host/Host_H6_<collector_name>/
<collector_name>                      Error            /error_logs/s15_<collector_name>.txt
<collector_name>                    Skipped            /error_logs/i13_<collector_name>.txt
```

**Collection Statuses:**
- **Complete** ✅ - Data successfully collected
- **Error** ❌ - Collection failed (check error_logs/)
- **Partial** ⚠️ - Some data collected, some errors
- **Skipped** ⏭️ - Not applicable for this platform

## Troubleshooting

### Connection Issues

**BMC Not Accessible:**
```shell
# Test BMC connectivity with IPMI
ipmitool -I lanplus -H <BMC_IP> -U <USER> -P <PASS> chassis status

# Test Redfish API
curl -k -u <USER>:<PASS> https://<BMC_IP>/redfish/v1/

# Test SSH access to BMC
ssh <USER>@<BMC_IP>
```

**Firewall Rules:**
Ensure the following ports are accessible:
- **Port 443** - HTTPS/Redfish
- **Port 22** - SSH
- **Port 623** - IPMI-over-LAN

**Network Configuration:**
- Verify BMC IP address is correct and reachable
- Check that BMC and client are on same network or routable
- For segmented networks, consider split log collection

### Collection Failures

**Platform Detection Failed:**
```shell
# Manually specify baseboard
python -m src.tool.main collect -i <BMC_IP> -u <USER> -p <PASS> -b "<baseboard>"

# List available baseboards
python -m src.tool.main list-baseboards
```

**Missing Tools on Target System:**

For host collection, ensure required tools are installed:
```shell
# On target host
sudo apt-get install nvme-cli pciutils dmidecode lshw
```

For NVIDIA-specific collectors, install:
- NVIDIA Graphics Driver (for nvidia-smi, nvidia-bug-report)
- nvidia-fabricmanager (for fabric manager collector)
- doca-sosreport v4.8.0+ (for sos-report collector)

**Credential Issues:**
- Verify BMC credentials have administrative privileges
- Verify host credentials have sudo access
- Check for special characters in passwords (may need escaping)

### Analyzing Errors

**Check Execution Summary:**
```shell
cd nvdebug_logs_<date>_<time>/<dut_name>
cat Execution_Summary_Report.txt
```

**Review Error Logs:**
```shell
# List all error files
ls -la error_logs/

# View specific error
cat error_logs/<collector_name>_errors.txt
```

### Common Issues

**Issue: "Platform detection failed"**
- **Solution**: Specify baseboard manually with `-b` flag

**Issue: "Connection timeout"**
- **Solution**: Check network connectivity, firewall rules, and BMC status

**Issue: "Permission denied" errors**
- **Solution**: Verify credentials have administrative/sudo privileges

**Issue: "Collector skipped"**
- **Solution**: Normal behavior - collector may not apply to your platform

**Issue: "Python version mismatch"**
- **Solution**: Ensure Python 3.12 is installed and in use

### Performance Issues

**Collection Taking Too Long:**
- Some collectors (especially with `-vv`) can take hours
- Network bandwidth affects collection speed
- Consider collecting OOB and IB separately if needed

**Disk Space:**
- Ensure adequate free space (2GB minimum, more for large systems)
- Monitor archive sizes for heavily-used rack systems
- Old logs can be cleaned up periodically

## Additional Resources

### Support
- **NVIDIA Support Portal**: https://support.nvidia.com
- **NVIDIA Documentation**: https://docs.nvidia.com
- **Developer Forums**: https://forums.developer.nvidia.com

### Version Information
Check your nvdebug version:
```shell
python -m src.tool.main --version
```

## Contributing to OPEN-NVDEBUG

Refer to CONTRIBUTING.md for contribution guidelines.