import { defineStore } from 'pinia'
import type { Manifest, DUT, FileEntry, ErrorEntry, CollectorDef, CollectionSummary, TimingData, PreflightData, DependencyCheckData } from '@/types/manifest'
import { SUPPORTED_SCHEMA_VERSIONS } from '@/types/manifest'

declare global {
  interface Window {
    __MANIFEST__?: Manifest
  }
}

function validateAndNormalize(raw: any): Manifest {
  const schemaVersion = raw?.schema_version ?? raw?.version ?? '1.0'

  if (!SUPPORTED_SCHEMA_VERSIONS.includes(schemaVersion)) {
    console.warn(
      `[ManifestStore] Unknown schema version "${schemaVersion}". ` +
      `Supported: ${SUPPORTED_SCHEMA_VERSIONS.join(', ')}. Attempting graceful load.`
    )
  }

  return {
    schema_version: schemaVersion,
    version: raw?.version ?? '1.0',
    generated_at: raw?.generated_at ?? '',
    tool_version: raw?.tool_version ?? 'unknown',
    tool_config: raw?.tool_config ?? { collection_level: 'unknown', execution_mode: 'unknown', baseboard: 'unknown' },
    duts: Array.isArray(raw?.duts) ? raw.duts : [],
    collector_catalog: Array.isArray(raw?.collector_catalog) ? raw.collector_catalog : [],
    timing: raw?.timing ?? { total_duration: 0, component_timing: {}, per_dut: [], per_service: [] },
    file_index: Array.isArray(raw?.file_index) ? raw.file_index : [],
    errors: Array.isArray(raw?.errors) ? raw.errors : [],
    preflight: raw?.preflight ?? { per_dut: [] },
    dependency_check: raw?.dependency_check ?? { per_dut: [] },
    collection_summary: raw?.collection_summary ?? {
      total_duts: 0, total_collectors_executed: 0, total_collectors_in_catalog: 0,
      total_collectors_filtered_out: 0, total_log_size: 0, total_runtime: 0,
      overall_collection_pct: 0, status_counts: { success: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 },
    },
  }
}

export const useManifestStore = defineStore('manifest', {
  state: () => ({
    manifest: null as Manifest | null,
    loaded: false,
    loadError: null as string | null,
  }),

  getters: {
    duts: (state): DUT[] => state.manifest?.duts ?? [],
    fileIndex: (state): FileEntry[] => state.manifest?.file_index ?? [],
    errors: (state): ErrorEntry[] => state.manifest?.errors ?? [],
    collectorCatalog: (state): CollectorDef[] => state.manifest?.collector_catalog ?? [],
    timing: (state): TimingData | null => state.manifest?.timing ?? null,
    preflight: (state): PreflightData | null => state.manifest?.preflight ?? null,
    dependencyCheck: (state): DependencyCheckData | null => state.manifest?.dependency_check ?? null,
    collectionSummary: (state): CollectionSummary | null => state.manifest?.collection_summary ?? null,
    toolVersion: (state): string => state.manifest?.tool_version ?? 'unknown',
    generatedAt: (state): string => state.manifest?.generated_at ?? '',
    schemaVersion: (state): string => state.manifest?.schema_version ?? '1.0',

    dutById: (state) => {
      return (id: string): DUT | undefined =>
        state.manifest?.duts.find(d => d.id === id)
    },

    filesByDut: (state) => {
      return (dutId: string): FileEntry[] =>
        (state.manifest?.file_index ?? []).filter(f => f.dut_id === dutId)
    },

    filesByCollector: (state) => {
      return (collectorId: string): FileEntry[] =>
        (state.manifest?.file_index ?? []).filter(f => f.collector_id === collectorId)
    },

    globalStatusCounts: (state) => {
      if (!state.manifest?.collection_summary) return { success: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 }
      return state.manifest.collection_summary.status_counts
    },
  },

  actions: {
    loadFromWindow() {
      try {
        if (window.__MANIFEST__) {
          this.manifest = validateAndNormalize(window.__MANIFEST__)
          this.loaded = true
          this.loadError = null
        }
      } catch (e) {
        this.loadError = `Failed to load manifest: ${e}`
        console.error('[ManifestStore]', this.loadError)
      }
    },

    loadFromJson(data: any) {
      try {
        this.manifest = validateAndNormalize(data)
        this.loaded = true
        this.loadError = null
      } catch (e) {
        this.loadError = `Failed to parse manifest: ${e}`
        console.error('[ManifestStore]', this.loadError)
      }
    },
  },
})
