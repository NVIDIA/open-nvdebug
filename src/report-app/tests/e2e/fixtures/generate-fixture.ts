/**
 * Generate a test fixture report directory for e2e tests.
 * Run: npx tsx tests/e2e/fixtures/generate-fixture.ts
 */
import { writeFileSync, mkdirSync, copyFileSync, existsSync, readFileSync, readdirSync } from 'fs'
import { join } from 'path'

const FIXTURE_DIR = join(__dirname, 'report')

// Clean and create
mkdirSync(join(FIXTURE_DIR, 'reports', 'assets'), { recursive: true })
mkdirSync(join(FIXTURE_DIR, 'DUT_1', 'redfish'), { recursive: true })
mkdirSync(join(FIXTURE_DIR, 'DUT_1', 'host'), { recursive: true })
mkdirSync(join(FIXTURE_DIR, 'DUT_1', '.metadata'), { recursive: true })

// Sample manifest
const manifest = {
  version: '1.0',
  generated_at: '2026-03-18T14:30:00Z',
  tool_version: '2.1.0',
  tool_config: { collection_level: 'L2', execution_mode: 'RemoteClient', baseboard: 'HGX_H100' },
  duts: [{
    id: 'DUT_1', baseboard: 'HGX_H100', node_type: 'Compute', bmc_ip: '10.0.0.1',
    collector_groups: [{
      name: 'redfish', service_type: 'redfish',
      collectors: [
        { id: 'R1', name: 'Systems', status: 'success', execution_time: 5.2, start_time: '2026-03-18T14:30:00Z', end_time: '2026-03-18T14:30:05Z', reason: '', dependencies: [], collection_level: 'L1', files: [{ path: 'DUT_1/redfish/Systems.json', size: 1024, type: 'json', collector_id: 'R1' }], stage_timing: { validation: 0.1, discovery: 0.5, execution: 4.0, post_processing: 0.6 } },
        { id: 'R2', name: 'Managers', status: 'error', execution_time: 30, start_time: '2026-03-18T14:30:05Z', end_time: '2026-03-18T14:30:35Z', reason: 'Connection timeout', dependencies: [], collection_level: 'L1', files: [], stage_timing: { validation: 0.1, discovery: null, execution: null, post_processing: null } },
      ],
      total_execution_time: 35.2,
    }, {
      name: 'host', service_type: 'host',
      collectors: [
        { id: 'H1', name: 'dmesg', status: 'success', execution_time: 2.1, start_time: '2026-03-18T14:30:00Z', end_time: '2026-03-18T14:30:02Z', reason: '', dependencies: [], collection_level: 'L1', files: [{ path: 'DUT_1/host/dmesg.log', size: 5242880, type: 'log', collector_id: 'H1' }], stage_timing: { validation: 0.1, discovery: null, execution: 1.8, post_processing: 0.2 } },
      ],
      total_execution_time: 2.1,
    }],
    status_summary: { success: 2, error: 1, partial: 0, skipped: 0, not_ran: 0 },
    overall_status: 'error',
    execution_time: 37.3,
    log_size: 5243904,
    system_info: { model: 'DGXH100', part_number: '123-456', serial_number: 'ABC789', firmware: [{ component: 'BMC', version: '01.02.03', date: '2026-01-15' }] },
  }],
  collector_catalog: [],
  timing: { total_duration: 37.3, component_timing: { tool_init: 0.5, config_load: 0.2, dut_init: 1.0, preflight: 2.0, collection: 30.0, report_generation: 3.0, metadata_write: 0.5, cleanup: 0.1 }, per_dut: [{ dut_id: 'DUT_1', duration: 37.3, collectors: [{ id: 'R1', name: 'Systems', group: 'redfish', duration: 5.2, start_time: '2026-03-18T14:30:00Z', end_time: '2026-03-18T14:30:05Z', status: 'success', stage_timing: { validation: 0.1, discovery: 0.5, execution: 4.0, post_processing: 0.6 } }] }], per_service: [{ service: 'redfish', total_collectors: 2, total_duration: 35.2 }, { service: 'host', total_collectors: 1, total_duration: 2.1 }] },
  file_index: [
    { path: 'DUT_1/redfish/Systems.json', size: 1024, type: 'json', collector_id: 'R1', dut_id: 'DUT_1', collector_group: 'redfish', collector_name: 'Systems' },
    { path: 'DUT_1/host/dmesg.log', size: 5242880, type: 'log', collector_id: 'H1', dut_id: 'DUT_1', collector_group: 'host', collector_name: 'dmesg' },
  ],
  errors: [{ dut_id: 'DUT_1', collector_id: 'R2', collector_name: 'Managers', collector_group: 'redfish', message: 'Connection timeout after 30s', timestamp: '2026-03-18T14:30:05Z' }],
  preflight: { per_dut: [{ dut_id: 'DUT_1', checks: [{ name: 'redfish_connectivity', group: 'redfish', status: 'pass', details: 'BMC reachable' }] }] },
  collection_summary: { total_duts: 1, total_collectors_executed: 3, total_collectors_in_catalog: 50, total_collectors_filtered_out: 47, total_log_size: 5243904, total_runtime: 37.3, overall_collection_pct: 66.7, status_counts: { success: 2, error: 1, partial: 0, skipped: 0, not_ran: 0 } },
}

// Write sample files
writeFileSync(join(FIXTURE_DIR, 'DUT_1', 'redfish', 'Systems.json'), JSON.stringify({ '@odata.id': '/redfish/v1/Systems', '@odata.type': '#ComputerSystemCollection.ComputerSystemCollection', Members: [{ '@odata.id': '/redfish/v1/Systems/1' }] }, null, 2))
writeFileSync(join(FIXTURE_DIR, 'DUT_1', 'host', 'dmesg.log'), Array.from({ length: 100 }, (_, i) => `[${i}.000000] kernel: log line ${i}`).join('\n'))

// Read the built index.html and inject manifest
const distDir = join(__dirname, '..', '..', '..', 'dist')
if (existsSync(join(distDir, 'index.html'))) {
  let html = readFileSync(join(distDir, 'index.html'), 'utf-8')
  const scriptTag = `<script>window.__MANIFEST__ = ${JSON.stringify(manifest)};</script>`
  html = html.replace('</head>', `${scriptTag}\n</head>`)
  writeFileSync(join(FIXTURE_DIR, 'reports', 'index.html'), html)

  // Copy assets
  const assetsDir = join(distDir, 'assets')
  if (existsSync(assetsDir)) {
    mkdirSync(join(FIXTURE_DIR, 'reports', 'assets'), { recursive: true })
    for (const file of readdirSync(assetsDir)) {
      copyFileSync(join(assetsDir, file), join(FIXTURE_DIR, 'reports', 'assets', file))
    }
  }
}

console.log('Test fixture generated at:', FIXTURE_DIR)
