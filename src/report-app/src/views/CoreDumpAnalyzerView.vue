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
    <PageLoader v-if="!manifestStore.loaded" message="Loading core dump handoff..." />

    <template v-else>
      <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'OpenBMC Core Dumps' }]" />

      <div class="page-header">
        <div>
          <h2 class="nv-page__title">OpenBMC Core Dump Handoff</h2>
          <p class="page-subtitle">
            Analyzer inputs and collection provenance for a manual handoff
          </p>
        </div>
        <a
          v-if="analyzerUrl"
          :href="analyzerUrl"
          target="_blank"
          rel="noopener noreferrer"
          class="nv-btn nv-btn--primary"
        >
          Open Configured Analyzer
        </a>
      </div>

      <NvCallout variant="info" title="Manual handoff only">
        NVDebug indexed artifacts already present in this collection. It did not
        transmit a core file or its metadata to the analyzer. Review the
        sensitive artifact and upload it manually only when authorized.
      </NvCallout>

      <NvCallout
        v-if="!analyzerUrl"
        variant="info"
        title="Analysis destination not configured"
      >
        This report build does not include an approved analysis destination.
        Follow your deployment's documented handoff process; collection and
        core-dump metadata remain available below.
      </NvCallout>

      <NvCallout variant="warning" title="Sensitive diagnostic data">
        {{ privacyNotice }}
      </NvCallout>

      <NvCallout
        v-if="!archiveScan.complete || scanWarnings.length"
        variant="warning"
        title="Core-dump indexing incomplete"
      >
        <p>
          {{ archiveScan.uninspected_archive_count }} controller archive(s)
          were unavailable, skipped, unsupported, or only partially inspected.
          The collected artifacts remain available; review the paths and reasons
          below before concluding that no additional core exists.
        </p>
        <p v-if="archiveScan.uninspected_archive_details_omitted">
          {{ archiveScan.uninspected_archive_details_omitted }} additional
          archive detail(s) were omitted from this bounded handoff.
        </p>
        <ul class="detail-list">
          <li v-for="warning in scanWarnings" :key="warning">
            {{ warning }}
          </li>
          <li
            v-for="archive in archiveScan.uninspected_archives"
            :key="`${archive.status}:${archive.artifact_path}`"
          >
            {{ archive.artifact_path }} — {{ archive.status }}:
            {{ archive.reason }}
          </li>
        </ul>
      </NvCallout>

      <div class="summary-grid">
        <div class="nv-card">
          <span>Core dumps</span>
          <strong>{{ summary.core_dump_count }}</strong>
        </div>
        <div class="nv-card">
          <span>Handoff-ready</span>
          <strong class="ready">{{ summary.analyzer_ready_count }}</strong>
        </div>
        <div class="nv-card">
          <span>Need metadata or preparation</span>
          <strong class="needs-data">{{ summary.needs_metadata_count }}</strong>
        </div>
      </div>

      <div v-if="coreDumps.length === 0" class="nv-card empty-card">
        No OpenBMC core dump artifacts were detected in this collection. Older
        manifests without the optional handoff section remain supported.
      </div>

      <div v-else class="core-list">
        <article
          v-for="core in coreDumps"
          :key="`${core.source_dut}:${core.artifact_path}:${core.archive_member_path ?? ''}`"
          class="nv-card core-card"
        >
          <div class="core-card__header">
            <div class="core-card__identity">
              <router-link
                v-if="isCollectedFile(core.artifact_path)"
                :to="`/file/${encodeURIComponent(core.artifact_path)}`"
                class="core-path"
              >
                {{ coreReference(core) }}
              </router-link>
              <code v-else class="core-path core-path--plain">
                {{ coreReference(core) }}
              </code>
              <div class="muted">
                {{ formatBytes(core.size_bytes) }} &middot;
                {{ displayValue(core.validation) }}
              </div>
            </div>
            <span
              :class="[
                'readiness',
                core.ready_for_analyzer
                  ? 'readiness--ready'
                  : 'readiness--missing',
              ]"
            >
              {{ core.ready_for_analyzer ? 'Handoff-ready' : 'Action required' }}
            </span>
          </div>

          <dl class="metadata-grid">
            <div>
              <dt>
                {{ core.archive_member_path ? 'Collected archive' : 'Exact core path' }}
              </dt>
              <dd><code>{{ displayValue(core.artifact_path) }}</code></dd>
            </div>
            <div v-if="core.archive_member_path">
              <dt>Exact core member</dt>
              <dd><code>{{ core.archive_member_path }}</code></dd>
            </div>
            <div>
              <dt>OpenBMC commit</dt>
              <dd :class="{ missing: !core.openbmc_commit }">
                <code>{{ displayValue(core.openbmc_commit) }}</code>
              </dd>
            </div>
            <div>
              <dt>Machine</dt>
              <dd :class="{ missing: !core.machine }">
                <code>{{ displayValue(core.machine) }}</code>
              </dd>
            </div>
            <div>
              <dt>Service</dt>
              <dd :class="{ missing: !core.service }">
                <code>{{ displayValue(core.service) }}</code>
              </dd>
            </div>
            <div>
              <dt>Source DUT</dt>
              <dd>{{ displayValue(core.source_dut) }}</dd>
            </div>
            <div>
              <dt>Baseboard</dt>
              <dd>{{ displayValue(core.baseboard) }}</dd>
            </div>
            <div>
              <dt>PID</dt>
              <dd>{{ displayValue(core.pid) }}</dd>
            </div>
            <div>
              <dt>Crash time</dt>
              <dd>{{ displayValue(core.timestamp) }}</dd>
            </div>
            <div>
              <dt>Collector</dt>
              <dd>{{ collectorLabel(core) }}</dd>
            </div>
            <div>
              <dt>Compression</dt>
              <dd>{{ displayValue(core.compression) }}</dd>
            </div>
          </dl>

          <div class="source-row">
            <strong>Metadata sources:</strong>
            commit={{ metadataSource(core, 'openbmc_commit') }},
            machine={{ metadataSource(core, 'machine') }},
            service={{ metadataSource(core, 'service') }}
          </div>

          <NvCallout
            v-if="core.missing_required_metadata.length"
            variant="warning"
            title="Missing required metadata"
          >
            {{ core.missing_required_metadata.join(', ') }}. Supply these values
            before the manual analyzer handoff.
          </NvCallout>

          <NvCallout
            v-if="core.preparation_required.length"
            variant="warning"
            title="Preparation required"
          >
            <ul class="detail-list">
              <li
                v-for="instruction in core.preparation_required"
                :key="instruction"
              >
                {{ instruction }}
              </li>
            </ul>
          </NvCallout>

          <ul v-if="core.warnings.length" class="detail-list warnings">
            <li v-for="warning in core.warnings" :key="warning">
              {{ warning }}
            </li>
          </ul>
        </article>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import NvCallout from '@/components/common/NvCallout.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import { useManifestStore } from '@/stores/manifest'
import type { OpenBMCCoreDumpRecord } from '@/types/manifest'

const manifestStore = useManifestStore()

const coreDumps = computed(
  () => manifestStore.openBMCCoreDumps?.core_dumps ?? [],
)
const summary = computed(
  () =>
    manifestStore.openBMCCoreDumps?.summary ?? {
      core_dump_count: 0,
      analyzer_ready_count: 0,
      needs_metadata_count: 0,
    },
)
const analyzerUrl = computed(
  () => manifestStore.openBMCCoreDumps?.analyzer.url ?? null,
)
const privacyNotice = computed(
  () =>
    manifestStore.openBMCCoreDumps?.privacy.notice ??
    'Core dumps can contain sensitive process memory. This handoff did not upload them to the analyzer.',
)
const scanWarnings = computed(
  () => manifestStore.openBMCCoreDumps?.scan_warnings ?? [],
)
const archiveScan = computed(
  () =>
    manifestStore.openBMCCoreDumps?.archive_scan ?? {
      complete: true,
      archives_inspected: 0,
      compressed_bytes_inspected: 0,
      decompressed_bytes_consumed: 0,
      members_inspected: 0,
      uninspected_archive_count: 0,
      uninspected_archive_details_omitted: 0,
      uninspected_archives: [],
    },
)
const collectedPaths = computed(
  () => new Set(manifestStore.fileIndex.map(file => file.path)),
)

function isCollectedFile(path: string): boolean {
  return collectedPaths.value.has(path)
}

function collectorLabel(core: OpenBMCCoreDumpRecord): string {
  const label = [core.collector.id, core.collector.name]
    .filter(Boolean)
    .join(' \u00b7 ')
  return label || core.collector.path || 'Missing'
}

function coreReference(core: OpenBMCCoreDumpRecord): string {
  return core.archive_member_path
    ? `${core.artifact_path}::${core.archive_member_path}`
    : displayValue(core.artifact_path)
}

function metadataSource(
  core: OpenBMCCoreDumpRecord,
  key: string,
): string {
  return core.metadata_sources[key] || 'not recorded'
}

function displayValue(value: unknown): string {
  return value === null || value === undefined || value === ''
    ? 'Missing'
    : String(value)
}

function formatBytes(bytes: number): string {
  if (!bytes) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const index = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1,
  )
  return `${(bytes / Math.pow(1024, index)).toFixed(index ? 1 : 0)} ${units[index]}`
}
</script>

<style scoped>
.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin: 16px 0 20px;
}
.page-subtitle {
  margin: 4px 0 0;
  color: var(--nv-text-secondary);
  font-size: 0.8125rem;
}
.nv-callout + .nv-callout {
  margin-top: 10px;
}
.summary-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin: 16px 0;
}
.summary-grid .nv-card {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.summary-grid span {
  color: var(--nv-text-secondary);
}
.summary-grid strong {
  font-size: 1.5rem;
}
.ready {
  color: var(--nv-success);
}
.needs-data,
.missing {
  color: var(--nv-warning);
}
.core-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.core-card {
  padding: 18px;
}
.core-card__header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: flex-start;
  margin-bottom: 16px;
}
.core-card__identity {
  min-width: 0;
}
.core-path {
  color: var(--nv-accent);
  font-family: var(--nv-font-mono);
  font-weight: 600;
  overflow-wrap: anywhere;
}
.core-path--plain {
  color: var(--nv-text-primary);
}
.muted,
.source-row {
  color: var(--nv-text-tertiary);
  font-size: 0.6875rem;
  margin-top: 4px;
}
.source-row {
  margin: 0 0 12px;
  overflow-wrap: anywhere;
}
.readiness {
  border-radius: 999px;
  font-size: 0.6875rem;
  font-weight: 700;
  padding: 4px 9px;
  white-space: nowrap;
}
.readiness--ready {
  color: var(--nv-success);
  background: color-mix(in srgb, var(--nv-success) 12%, transparent);
}
.readiness--missing {
  color: var(--nv-warning);
  background: color-mix(in srgb, var(--nv-warning) 12%, transparent);
}
.metadata-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
  margin: 0 0 14px;
}
.metadata-grid div {
  min-width: 0;
}
.metadata-grid dt {
  color: var(--nv-text-tertiary);
  font-size: 0.6875rem;
  margin-bottom: 3px;
}
.metadata-grid dd {
  color: var(--nv-text-primary);
  font-size: 0.8125rem;
  margin: 0;
  overflow-wrap: anywhere;
}
.metadata-grid dd.missing {
  color: var(--nv-warning);
  font-weight: 600;
}
.detail-list {
  margin: 0;
  padding-left: 18px;
}
.warnings {
  color: var(--nv-text-secondary);
  font-size: 0.75rem;
  margin-top: 10px;
}
.empty-card {
  color: var(--nv-text-secondary);
  text-align: center;
  padding: 32px;
}
@media (max-width: 800px) {
  .summary-grid,
  .metadata-grid {
    grid-template-columns: 1fr;
  }
  .page-header,
  .core-card__header {
    flex-direction: column;
  }
}
</style>
