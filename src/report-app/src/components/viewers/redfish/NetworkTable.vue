<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

<template>
  <div class="nv-page">
    <div v-if="interfaces.length === 0" class="nv-empty">
      No network interface data available
    </div>

    <template v-else>
      <h3 class="nv-section-subtitle">Network Interfaces ({{ interfaces.length }})</h3>
      <div class="nv-table-viewport" style="max-height: 500px;">
        <table class="nv-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>MAC Address</th>
              <th>IPv4 Address</th>
              <th>IPv6 Address</th>
              <th>VLAN</th>
              <th>Speed</th>
              <th>Link</th>
              <th>Health</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="iface in interfaces" :key="iface.id">
              <td style="font-weight: 600;">{{ iface.name }}</td>
              <td><code class="mono" style="font-size: 0.75rem;">{{ iface.mac || '—' }}</code></td>
              <td>{{ iface.ipv4 || '—' }}</td>
              <td class="ipv6-cell">{{ iface.ipv6 || '—' }}</td>
              <td>
                <span v-if="iface.vlanId" class="nv-badge nv-badge--accent">VLAN {{ iface.vlanId }}</span>
                <span v-else style="color: var(--nv-text-tertiary);">—</span>
              </td>
              <td>{{ iface.speed || '—' }}</td>
              <td>
                <span
                  class="nv-badge"
                  :class="linkBadge(iface.linkStatus)"
                >{{ iface.linkStatus || 'Unknown' }}</span>
              </td>
              <td>
                <span
                  class="nv-badge"
                  :class="healthBadge(iface.health)"
                >{{ iface.health || '—' }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ data: any }>()

interface NetworkInterface {
  id: string
  name: string
  mac: string | null
  ipv4: string | null
  ipv6: string | null
  vlanId: number | null
  speed: string | null
  linkStatus: string
  health: string
}

function formatSpeed(mbps: number | null): string | null {
  if (mbps == null) return null
  if (mbps >= 1000) return (mbps / 1000) + ' Gbps'
  return mbps + ' Mbps'
}

const interfaces = computed<NetworkInterface[]>(() => {
  const members = props.data?.Members ?? (Array.isArray(props.data) ? props.data : [])
  return members.map((iface: any) => {
    const ipv4Addrs = iface.IPv4Addresses ?? iface.IPv4StaticAddresses ?? []
    const ipv6Addrs = iface.IPv6Addresses ?? iface.IPv6StaticAddresses ?? []
    const firstV4 = ipv4Addrs[0]
    const firstV6 = ipv6Addrs[0]

    return {
      id: iface.Id ?? iface['@odata.id'] ?? iface.Name ?? '',
      name: iface.Name ?? iface.Id ?? 'Interface',
      mac: iface.MACAddress ?? iface.PermanentMACAddress ?? null,
      ipv4: firstV4 ? (firstV4.Address ?? null) : null,
      ipv6: firstV6 ? (firstV6.Address ?? null) : null,
      vlanId: iface.VLAN?.VLANId ?? iface.VLANId ?? null,
      speed: formatSpeed(iface.SpeedMbps ?? null),
      linkStatus: iface.LinkStatus ?? iface.Status?.State ?? 'Unknown',
      health: iface.Status?.Health ?? '',
    }
  })
})

function linkBadge(status: string): string {
  switch (status?.toLowerCase()) {
    case 'linkup': return 'nv-badge--success'
    case 'linkdown': return 'nv-badge--error'
    case 'nolink': return 'nv-badge--error'
    default: return 'nv-badge--neutral'
  }
}

function healthBadge(health: string): string {
  switch (health?.toLowerCase()) {
    case 'ok': return 'nv-badge--success'
    case 'warning': return 'nv-badge--warning'
    case 'critical': return 'nv-badge--error'
    default: return 'nv-badge--neutral'
  }
}
</script>

<style scoped>
.ipv6-cell {
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
