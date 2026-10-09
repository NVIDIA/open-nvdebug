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

export type ConcurrencyMode = 'conservative' | 'fixed' | 'adaptive' | 'unknown'
export type ConcurrencySchedulerStatus = 'not_started' | 'running' | 'completed' | 'interrupted' | 'unknown'
export type ConcurrencyDecisionAction = 'start' | 'hold' | 'increase' | 'decrease' | 'stop' | 'unknown'

export interface ConcurrencyPressureSignals {
  eventLoopLagSeconds: number | null
  cpuUtilization: number | null
  cgroupThrottlingRatio: number | null
  memoryHeadroomRatio: number | null
  fileDescriptorUtilization: number | null
  pidUtilization: number | null
  cgroupOomEvents: number
  completedOperations: number | null
  remoteEvents: Record<string, number>
  transportLatencyP95Seconds: number | null
}

export interface ConcurrencyDecisionProgress {
  admissions: number
  completedOperations: number
  activeOperations: number
  activeWeight: number
  queuedOperations: number
}

export interface ConcurrencyDecisionPoint {
  timestamp: string | null
  elapsedSeconds: number
  action: ConcurrencyDecisionAction
  previousLimit: number
  newLimit: number
  reasons: string[]
  signals: ConcurrencyPressureSignals | null
  progress: ConcurrencyDecisionProgress | null
  cumulativeCompletedOperations: number
}

export interface ConcurrencyServiceMetric {
  service: string
  completedOperations: number
  activeSecondsTotal: number
  activeSecondsAverage: number
  peakActiveOperations: number
}

export interface ConcurrencyCountMetric {
  label: string
  count: number
}

export interface ConcurrencySchedulerAnalysis {
  schemaVersion: string | number | null
  status: ConcurrencySchedulerStatus
  mode: ConcurrencyMode
  startedAt: string | null
  completedAt: string | null
  initialLimit: number
  minimumLimit: number
  maximumLimit: number
  finalLimit: number
  sampleIntervalSeconds: number | null
  healthyWindowsRequired: number | null
  increaseStep: number | null
  decreaseRatio: number | null
  hardDecreaseRatio: number | null
  cooldownSeconds: number | null
  endpointCooldownSeconds: number | null
  plannedOperations: number
  skippedOperations: number
  weightedDemand: number
  dutCount: number
  serviceLaneCount: number
  perDutRedfishLimit: number | null
  admissions: number
  completedOperations: number
  completionPercent: number | null
  queueWaitSecondsTotal: number
  queueWaitSecondsAverage: number
  queueWaitSecondsMax: number
  activeSecondsTotal: number
  activeSecondsAverage: number
  activeSecondsMax: number
  peakActiveOperations: number
  peakActiveWeight: number
  currentQueuedOperations: number
  peakQueuedOperations: number | null
  backfilledOperations: number | null
  queuedWallSeconds: number | null
  saturatedWhileQueuedSeconds: number | null
  runnableGapWeightSeconds: number | null
  fragmentationWeightSeconds: number | null
  utilizationWhileQueuedRatio: number | null
  saturationWhileQueuedRatio: number | null
  decisionTotal: number
  decisionRetained: number
  decisionDropped: number
  decisions: ConcurrencyDecisionPoint[]
  serviceMetrics: ConcurrencyServiceMetric[]
  remotePressureEvents: ConcurrencyCountMetric[]
  endpointCooldowns: ConcurrencyCountMetric[]
  warnings: string[]
}
