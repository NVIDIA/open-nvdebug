// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import type { CollectorResult as Collector, CollectorDef, DUT, PreflightCheck } from '@/types/manifest'
import { normalizePreflightStatus } from '@/utils/preflight'

// These semantic roles mirror the system-view extractors. Collector identities
// come from the report's own catalog/group metadata, never platform-specific IDs.
const FIELD_ROLES: Record<string, string[]> = {
  'bmc.version': ['manager_inventory', 'firmware_inventory_table', 'firmware_inventory_expanded', 'firmware_inventory_references', 'bmc_os_identity'],
  'bmc.os': ['bmc_os_identity'],
  'bmc.kernel': ['bmc_resource_snapshot'],
  'bmc.uptime': ['bmc_uptime'],
  'bmc.cpu': ['bmc_resource_snapshot'],
  'bmc.memory': ['bmc_resource_snapshot'],
  'bmc.disk': ['bmc_resource_snapshot'],
  'host.os': ['host_system_snapshot'],
  'host.kernel': ['host_system_snapshot'],
  'host.uptime': ['host_system_snapshot'],
  'host.cpu': ['host_system_snapshot'],
  'host.memory': ['host_system_snapshot', 'host_memory_snapshot'],
  'host.disk': ['host_system_snapshot'],
  'software.sbios': ['host_smbios'],
  'software.rm_driver_version': ['host_gpu_runtime'],
  'software.cuda_driver_version': ['host_gpu_runtime'],
  'software.dcgm_version': ['host_gpu_runtime'],
}

function roles(value: unknown): string[] {
  const values = Array.isArray(value) ? value.slice(0, 16) : [value]
  return values.filter((role): role is string => typeof role === 'string').map(role => role.trim().toLowerCase())
}

export function systemViewSources(dut: DUT | undefined, catalog: CollectorDef[]): Map<string, Collector[]> {
  const definitions = new Map(catalog.filter(definition => typeof definition.id === 'string').map(definition => [definition.id.toLowerCase(), definition]))
  const sources = new Map<string, Collector[]>()
  for (const group of dut?.collector_groups ?? []) {
    for (const collector of group.collectors) {
      const recordedRoles = roles(collector.report_role)
      const assigned = recordedRoles.length ? recordedRoles : roles(definitions.get(collector.id.toLowerCase())?.report_role)
      for (const role of new Set(assigned)) {
        const entries = sources.get(role) ?? []
        entries.push(collector)
        sources.set(role, entries)
      }
    }
  }
  return sources
}

/** Explain absent values using recorded source outcomes, without inventing a cause. */
export function systemViewValue(
  value: unknown,
  field: string,
  sources: Map<string, Collector[]>,
  preflightChecks: PreflightCheck[],
): string {
  if (value !== null && value !== undefined && value !== '') return String(value)
  const collectors = [...new Set((FIELD_ROLES[field] ?? []).flatMap(role => sources.get(role) ?? []))]
  if (collectors.length) {
    const reasons = collectors.slice(0, 3).map(collector => {
      if (collector.status === 'success') return `${collector.id}: completed, but this value was not found in the collected output`
      return `${collector.id}: ${collector.status}${collector.reason ? ` — ${collector.reason}` : ' — no reason recorded'}`
    })
    return `Not available — ${reasons.join('; ')}${collectors.length > 3 ? '; see collector details for other sources' : ''}.`
  }
  // Legacy reports may lack role provenance. Give relevant preflight context,
  // but do not claim that a failed check necessarily caused this missing field.
  const groups = field.startsWith('bmc.') ? ['bmc', 'ssh', 'bmc_ssh'] : ['host', 'host_ssh']
  if (field === 'bmc.version') groups.push('redfish')
  const failed = preflightChecks.find(check =>
    groups.includes(check.group.toLowerCase()) && normalizePreflightStatus(check.status) === 'fail',
  )
  if (failed) return `Not collected. Related preflight failure: ${failed.name}${failed.details ? ` — ${failed.details}` : ''}.`
  return 'Not collected — no reason was recorded in this report.'
}
