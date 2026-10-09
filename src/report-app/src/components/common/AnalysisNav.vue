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
  <div class="anav">
    <div v-for="section in sections" :key="section.title" class="anav__section">
      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 6px 12px; margin: 0; font-size: 0.5625rem;">{{ section.title }}</h4>
      <router-link
        v-for="link in section.links"
        :key="link.to"
        :to="link.to"
        class="nv-sidebar__link"
        style="font-size: 0.6875rem;"
        @click="$emit('navigate')"
      >{{ link.label }}</router-link>
    </div>
  </div>
</template>

<script setup lang="ts">
defineEmits<{ navigate: [] }>()

const sections = [
  {
    title: 'Insights',
    links: [
      { to: '/anomalies', label: 'Anomalies' },
      { to: '/co-failure', label: 'Co-Failure Analysis' },
      { to: '/error-timeline', label: 'Error Timeline' },
      { to: '/errors', label: 'Error Aggregation' },
    ],
  },
  {
    title: 'Coverage',
    links: [
      { to: '/service-health', label: 'Service Health' },
      { to: '/coverage', label: 'Coverage Matrix' },
      { to: '/efficiency', label: 'Collection Efficiency' },
      { to: '/stage-profiling', label: 'Stage Profiling' },
    ],
  },
  {
    title: 'Comparison',
    links: [
      { to: '/compare', label: 'DUT Comparison' },
      { to: '/firmware-compare', label: 'Firmware Comparison' },
      { to: '/compare-runs', label: 'Run Comparison' },
    ],
  },
  {
    title: 'Infrastructure',
    links: [
      { to: '/resources', label: 'Resource Usage' },
      { to: '/preflight-summary', label: 'Preflight Summary' },
      { to: '/dependencies', label: 'Dependency Graph' },
      { to: '/heatmap', label: 'Health Heatmap' },
    ],
  },
  {
    title: 'Tools',
    links: [
      { to: '/correlate', label: 'Log Correlation' },
      { to: '/diff', label: 'File Diff' },
      { to: '/timing/gantt', label: 'Execution Timeline' },
      { to: '/split', label: 'Split File View' },
    ],
  },
]
</script>

<style scoped>
.anav__section {
  margin-bottom: 2px;
}
:deep(.nv-sidebar__link.router-link-exact-active) {
  background: var(--nv-accent-subtle);
  color: var(--nv-accent);
  border-left-color: var(--nv-accent);
  font-weight: 600;
}
</style>
