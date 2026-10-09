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

export type RedfishResourceType =
  | 'thermal' | 'power' | 'sensors' | 'event-log'
  | 'systems' | 'managers' | 'chassis' | 'storage'
  | 'ethernet' | 'unknown'

/**
 * Detect Redfish resource type from JSON content.
 * Checks @odata.type first, then URI patterns, then structure heuristics.
 */
export function detectRedfishType(data: any): RedfishResourceType {
  if (!data || typeof data !== 'object') return 'unknown'

  const odataType = String(data['@odata.type'] ?? '').toLowerCase()
  const odataId = String(data['@odata.id'] ?? '').toLowerCase()

  if (odataType.includes('thermal') || odataId.includes('thermal')) return 'thermal'
  if (odataType.includes('power') || odataId.includes('power')) return 'power'
  if (odataType.includes('sensor') || odataId.includes('sensors')) return 'sensors'
  if (odataType.includes('logentry') || odataType.includes('logservice') || odataId.includes('logservices') || odataId.includes('entries')) return 'event-log'
  if (odataType.includes('computersystem') || odataId.includes('/systems/')) return 'systems'
  if (odataType.includes('manager') && !odataType.includes('storage') || odataId.endsWith('/managers')) return 'managers'
  if (odataType.includes('chassis') || odataId.includes('/chassis/')) return 'chassis'
  if (odataType.includes('storage') || odataType.includes('drive') || odataId.includes('/storage')) return 'storage'
  if (odataType.includes('ethernetinterface') || odataId.includes('ethernet')) return 'ethernet'

  // Heuristics
  if (data.Temperatures || data.Fans) return 'thermal'
  if (data.PowerSupplies || data.Voltages) return 'power'
  if (data.Members && Array.isArray(data.Members)) {
    const first = data.Members[0]
    if (first?.Severity || first?.EntryType) return 'event-log'
  }

  return 'unknown'
}
