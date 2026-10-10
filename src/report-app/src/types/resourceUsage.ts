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

export type ResourceHealthState = 'healthy' | 'degraded' | 'limited' | 'unavailable'
export type ResourceSignalState = 'clear' | 'observed' | 'critical' | 'unavailable'
export type ResourceLimitState = 'limited' | 'unlimited' | 'unavailable'

export interface ResourceSamplePoint {
  timestamp: string | null
  elapsedSeconds: number | null
  reason: string
  rssBytes: number | null
  processPeakRssBytes: number | null
  processSwapBytes: number | null
  cgroupMemoryBytes: number | null
  cgroupPeakMemoryBytes: number | null
  cgroupSwapBytes: number | null
  swapEvents: number | null
  cpuTotalSeconds: number | null
  cgroupCpuUsageSeconds: number | null
  cpuCores: number | null
  cgroupCpuCores: number | null
  availableCpus: number | null
  quotaPercent: number | null
  cgroupQuotaPercent: number | null
  physicalReadBytes: number | null
  physicalWriteBytes: number | null
  logicalReadBytes: number | null
  logicalWriteBytes: number | null
  physicalReadBytesPerSecond: number | null
  physicalWriteBytesPerSecond: number | null
  logicalReadBytesPerSecond: number | null
  logicalWriteBytesPerSecond: number | null
  throttledSeconds: number | null
  throttleEvents: number | null
  oomEvents: number | null
  oomKillEvents: number | null
  memoryHighEvents: number | null
  cpuPressureSomeAvg10: number | null
  cpuPressureFullAvg10: number | null
  memoryPressureSomeAvg10: number | null
  memoryPressureFullAvg10: number | null
  pidsCurrent: number | null
  pidsLimit: number | null
  threads: number | null
  openFds: number | null
  voluntaryContextSwitches: number | null
  involuntaryContextSwitches: number | null
  majorPageFaults: number | null
  captureWorkerCount: number | null
  captureActiveWorkers: number | null
  captureQueuedCalls: number | null
  captureWorkerCompletions: number | null
  captureWorkerFailures: number | null
  captureQueueWaitSecondsTotal: number | null
  captureUtilizationWhileQueuedPercent: number | null
  captureSaturationWhileQueuedPercent: number | null
  syntheticGap?: boolean
}

export interface ResourceLoadDiagnostics {
  filesAttempted: string[]
  filesLoaded: string[]
  missingFiles: string[]
  historySamplesLoaded: number | null
  malformedLines: number
  oversizedLines: number
  bytesRead: number
  byteLimitReached: boolean
  sampleLimitReached: boolean
  mainArtifactTruncated: boolean
  historySegmentsIgnored: number
}

export interface ResourceKpis {
  peakRssBytes: number | null
  processLifetimeHighWaterBytes: number | null
  finalRssBytes: number | null
  averageCpuCores: number | null
  availableCpus: number | null
  cpuQuotaPercent: number | null
  physicalReadBytes: number | null
  physicalWriteBytes: number | null
  logicalReadBytes: number | null
  logicalWriteBytes: number | null
  durationSeconds: number | null
}

export interface ResourceDataHealth {
  state: ResourceHealthState
  status: string
  samplesReported: number | null
  samplesRetained: number | null
  samplesLoaded: number
  samplesDropped: number | null
  samplesRotatedOut: number | null
  sampleWriteFailures: number | null
  malformedLines: number
  oversizedLines: number
  historySegmentsIgnored: number
  gapCount: number
  estimatedMissingSamples: number
  counterResets: number
  rotations: number | null
  expectedIntervalSeconds: number | null
  retainedFileCoveragePercent: number | null
  cadenceCoveragePercent: number | null
  scheduledPeriodicSamples: number | null
  missedScheduledIntervals: number | null
  maxSamplingJitterSeconds: number | null
  artifactWriteSucceeded: boolean | null
  byteLimitReached: boolean
  sampleLimitReached: boolean
  warnings: string[]
}

export interface ResourceScopeDiagnostic {
  id: string
  controller: string
  path: string
  role: 'current' | 'ancestor' | 'unknown'
  memoryCurrentBytes: number | null
  memoryPeakBytes: number | null
  memoryLifetimePeakBytes: number | null
  memoryLimitBytes: number | null
  memoryLimitState: ResourceLimitState
  swapCurrentBytes: number | null
  swapObservedPeakBytes: number | null
  swapLifetimeHighWaterBytes: number | null
  swapLimitBytes: number | null
  swapLimitState: ResourceLimitState
  swapCurrentSemantics: 'direct' | 'derived_memsw' | 'unavailable'
  memoryAndSwapCurrentBytes: number | null
  memoryAndSwapLimitBytes: number | null
  memoryAndSwapLimitState: ResourceLimitState
  swapEvents: number | null
  cpuUsageSeconds: number | null
  throttleEvents: number | null
  throttledSeconds: number | null
  oomEvents: number | null
  oomKillEvents: number | null
  memoryHighEvents: number | null
  cpuPressureSomeAvg10: number | null
  cpuPressureFullAvg10: number | null
  memoryPressureSomeAvg10: number | null
  memoryPressureFullAvg10: number | null
  pidsCurrent: number | null
  pidsLimit: number | null
  pidsLimitState: ResourceLimitState
  pidsMaxEvents: number | null
}

export interface ResourceRunSignals {
  memoryAccumulationState: ResourceSignalState
  baselineRssBytes: number | null
  rssGrowthBytes: number | null
  rssGrowthBytesPerHour: number | null
  peakRssRetainedPercent: number | null
  cpuPressureState: ResourceSignalState
  peakCpuBudgetPercent: number | null
  throttleEvents: number | null
  throttledSeconds: number | null
  peakCpuPressureSomeAvg10: number | null
  memoryPressureState: ResourceSignalState
  peakMemoryLimitPercent: number | null
  memoryHighEvents: number | null
  oomEvents: number | null
  oomKillEvents: number | null
  peakMemoryPressureSomeAvg10: number | null
  swapState: ResourceSignalState
  processObservedPeakSwapBytes: number | null
  cgroupObservedPeakSwapBytes: number | null
  swapEvents: number | null
}

export interface SchedulerDiagnostic {
  label: string
  value: string
  state: 'available' | 'unavailable'
}

export interface RequestCaptureAnalysis {
  schemaVersion: number | string | null
  status: string
  workerCount: number | null
  observationSeconds: number | null
  callsEnqueued: number | null
  callsCompleted: number | null
  workerFailures: number | null
  abandonedBeforeSubmission: number | null
  peakActiveWorkers: number | null
  peakQueuedCalls: number | null
  queueWaitSecondsTotal: number | null
  queueWaitSecondsAverage: number | null
  queueWaitSecondsMax: number | null
  queuedWallSeconds: number | null
  queuedCapacityWorkerSeconds: number | null
  queuedActiveWorkerSeconds: number | null
  saturatedWhileQueuedSeconds: number | null
  runnableGapWorkerSeconds: number | null
  utilizationWhileQueuedRatio: number | null
  saturationWhileQueuedRatio: number | null
  workerSecondsTotal: number | null
  workerUtilizationRatio: number | null
}

export interface ResourceMetricDefinition {
  metric: string
  definition: string
  source: string
}

export interface ResourceUsageAnalysis {
  schemaVersion: number | string | null
  status: string
  startedAt: string | null
  completedAt: string | null
  producerScope: string
  kpis: ResourceKpis
  signals: ResourceRunSignals
  health: ResourceDataHealth
  samples: ResourceSamplePoint[]
  scopes: ResourceScopeDiagnostic[]
  scheduler: SchedulerDiagnostic[]
  requestCapture: RequestCaptureAnalysis | null
  metricDefinitions: ResourceMetricDefinition[]
  monitorErrors: Array<{ timestamp: string | null; code: string }>
}

export interface AnalyzeResourceUsageOptions {
  artifact: unknown
  samples: ResourceSamplePoint[]
  diagnostics: ResourceLoadDiagnostics
  maxTimelinePoints?: number
}
