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

import { createRouter, createWebHashHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  { path: '/', name: 'dashboard', component: () => import('@/views/DashboardView.vue') },
  { path: '/dut/:dutId', name: 'dut', component: () => import('@/views/DutView.vue') },
  { path: '/dut/:dutId/preflight', name: 'preflight', component: () => import('@/views/PreflightView.vue') },
  { path: '/dut/:dutId/firmware', name: 'firmware', component: () => import('@/views/FirmwareView.vue') },
  { path: '/dut/:dutId/profile', name: 'dut-profile', component: () => import('@/views/DutProfileView.vue') },
  { path: '/dut/:dutId/:group', name: 'collector-group', component: () => import('@/views/CollectorGroupView.vue') },
  { path: '/dut/:dutId/:group/:collectorId', name: 'collector-detail', component: () => import('@/views/CollectorDetailView.vue') },
  { path: '/file/:encodedPath(.*)', name: 'file', component: () => import('@/views/FileView.vue') },
  { path: '/file-map', name: 'file-map', component: () => import('@/views/FileMapView.vue') },
  { path: '/coredumps', name: 'coredumps', component: () => import('@/views/CoreDumpAnalyzerView.vue') },
  { path: '/timing', name: 'timing', component: () => import('@/views/TimingView.vue') },
  { path: '/timing/gantt', name: 'gantt', component: () => import('@/views/GanttTimelineView.vue') },
  { path: '/status/:statusType', name: 'status-detail', component: () => import('@/views/StatusDetailView.vue') },
  { path: '/errors', name: 'errors', component: () => import('@/views/ErrorAggregationView.vue') },
  { path: '/anomalies', name: 'anomalies', component: () => import('@/views/AnomalyView.vue') },
  { path: '/service-health', name: 'service-health', component: () => import('@/views/ServiceHealthView.vue') },
  { path: '/efficiency', name: 'efficiency', component: () => import('@/views/CollectionEfficiencyView.vue') },
  { path: '/coverage', name: 'coverage', component: () => import('@/views/CoverageMatrixView.vue') },
  { path: '/firmware-compare', name: 'firmware-compare', component: () => import('@/views/FirmwareCompareView.vue') },
  { path: '/co-failure', name: 'co-failure', component: () => import('@/views/CoFailureView.vue') },
  { path: '/stage-profiling', name: 'stage-profiling', component: () => import('@/views/StageProfilingView.vue') },
  { path: '/resources', name: 'resources', component: () => import('@/views/ResourcesView.vue') },
  { path: '/error-timeline', name: 'error-timeline', component: () => import('@/views/ErrorTimelineView.vue') },
  { path: '/preflight-summary', name: 'preflight-summary', component: () => import('@/views/PreflightSummaryView.vue') },
  { path: '/diff', name: 'diff', component: () => import('@/views/DiffView.vue') },
  { path: '/dependencies', name: 'dependencies', component: () => import('@/views/DependencyGraphView.vue') },
  { path: '/heatmap', name: 'heatmap', component: () => import('@/views/HealthHeatmapView.vue') },
  { path: '/compare', name: 'compare', component: () => import('@/views/DutComparisonView.vue') },
  { path: '/correlate', name: 'correlate', component: () => import('@/views/LogCorrelationView.vue') },
  { path: '/redfish/:dutId/:collectorId', name: 'redfish', component: () => import('@/views/RedfishAwareView.vue') },
  { path: '/compare-runs', name: 'compare-runs', component: () => import('@/views/RunComparisonView.vue') },
  { path: '/split', name: 'split-file', component: () => import('@/views/SplitFileView.vue') },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

export default router
