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
  <div class="resource-layout">
    <aside class="nv-sidebar resource-sidebar">
      <AnalysisNav />
      <div class="resource-sidebar__divider"></div>
      <h4 class="nv-sidebar__section-title nv-glass--accent resource-sidebar__title">On this page</h4>
      <a
        v-for="anchor in anchors"
        :key="anchor.id"
        class="nv-sidebar__link resource-sidebar__link"
        :href="`#${anchor.id}`"
        @click.prevent="scrollToSection(anchor.id)"
      >
        {{ anchor.label }}
      </a>
    </aside>

    <main class="nv-page resource-page">
      <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Resource Usage' }]" />
      <div class="resource-heading">
        <div>
          <h2 class="nv-page__title">Resource Usage</h2>
          <p>nvdebug process, child-process, cgroup, scheduler, and sample-health telemetry</p>
        </div>
        <span v-if="analysis" :class="['resource-health', `resource-health--${analysis.health.state}`]" role="status" :aria-label="`Resource telemetry health: ${healthLabel(analysis.health.state)}`">
          {{ healthLabel(analysis.health.state) }}
        </span>
      </div>

      <NvCallout variant="info" title="Measurement scope">
        {{ measurementScopeDescription }}
        Linux process I/O includes writes made by the monitor itself. Missing metrics are shown as <strong>Unavailable</strong>, never as zero.
        Swap is available only in artifacts produced after the monitor began recording it.
      </NvCallout>

      <PageLoader v-if="loading" message="Loading bounded resource telemetry..." />

      <EmptyState
        v-else-if="waitingForDirectory"
        icon="file"
        title="Select the collection directory"
        description="Resource telemetry is read locally after the report directory has been selected."
      />

      <EmptyState
        v-else-if="missing"
        icon="data"
        title="Resource telemetry unavailable"
        description="This run does not contain .metadata/resource_usage.json. It may predate resource telemetry, or monitoring may not have produced the artifact. Other report analysis remains available."
      />

      <EmptyState
        v-else-if="loadError"
        icon="error"
        title="Resource telemetry could not be loaded"
        :description="loadError"
      />

      <template v-else-if="analysis">
        <section id="overview" class="resource-section">
          <h3 class="nv-section-title">Run overview</h3>
          <div class="resource-kpis">
            <StatCard label="Peak RSS" :value="formatMaybeBytes(analysis.kpis.peakRssBytes)" subtitle="Highest RSS sampled during monitoring" />
            <StatCard label="Process HWM" :value="formatMaybeBytes(analysis.kpis.processLifetimeHighWaterBytes)" subtitle="Kernel high-water since process start" color="purple" />
            <StatCard label="Final RSS" :value="formatMaybeBytes(analysis.kpis.finalRssBytes)" subtitle="Latest persisted sample" color="blue" />
            <StatCard label="Average CPU" :value="formatMaybeNumber(analysis.kpis.averageCpuCores, ' cores')" subtitle="Process + completed children" color="purple" />
            <StatCard label="CPU budget used" :value="formatMaybeNumber(analysis.kpis.cpuQuotaPercent, '%')" :subtitle="cpuBudgetSubtitle" color="orange" />
            <StatCard label="Physical reads" :value="formatMaybeBytes(analysis.kpis.physicalReadBytes)" subtitle="Storage-submitted bytes" color="blue" />
            <StatCard label="Physical writes" :value="formatMaybeBytes(analysis.kpis.physicalWriteBytes)" subtitle="Storage-submitted bytes" color="orange" />
          </div>

          <NvCallout
            v-for="warning in analysis.health.warnings"
            :key="warning"
            :variant="analysis.health.state === 'degraded' ? 'warning' : 'info'"
            title="Telemetry health"
            class="resource-warning"
          >
            {{ warning }}
          </NvCallout>
        </section>

        <section id="signals" class="resource-section">
          <h3 class="nv-section-title">Run signals</h3>
          <div class="resource-signal-grid">
            <article v-for="signal in signalCards" :key="signal.label" :class="['nv-card', 'resource-signal', `resource-signal--${signal.state}`]">
              <div class="resource-signal__heading">
                <h4>{{ signal.label }}</h4>
                <span>{{ signalStateLabel(signal.state) }}</span>
              </div>
              <strong>{{ signal.value }}</strong>
              <p>{{ signal.detail }}</p>
            </article>
          </div>
          <p class="resource-footnote">Signals are conservative diagnostics, not causal findings. In particular, RSS growth can identify accumulation worth investigating but cannot prove a memory leak.</p>
        </section>

        <section id="timelines" class="resource-section">
          <h3 class="nv-section-title">Resource timelines</h3>
          <div class="resource-chart-grid">
            <article class="nv-card resource-panel">
              <h4>Memory</h4>
              <p>Process RSS/swap and producer-marked current cgroup memory/swap. A current cgroup can still include sibling tasks.</p>
              <ResourceTimelineChart
                :points="analysis.samples"
                :series="memorySeries"
                y-axis-title="MiB"
                value-suffix=" MiB"
                :divisor="MIB"
                accessibility-label="Memory and swap timeline"
              />
            </article>
            <article class="nv-card resource-panel">
              <h4>CPU</h4>
              <p>Process CPU is shown against its effective budget. Current-scope cgroup CPU is separate because it can include sibling tasks and is never divided by the process budget.</p>
              <ResourceTimelineChart
                :points="analysis.samples"
                :series="cpuSeries"
                y-axis-title="CPU cores"
                value-suffix=" cores"
                accessibility-label="CPU usage and available budget timeline"
              />
            </article>
            <article class="nv-card resource-panel resource-panel--wide">
              <h4>I/O throughput</h4>
              <p>Physical storage traffic is kept distinct from logical syscall traffic.</p>
              <ResourceTimelineChart
                :points="analysis.samples"
                :series="ioSeries"
                y-axis-title="KiB/s"
                value-suffix=" KiB/s"
                :divisor="KIB"
                accessibility-label="Physical and logical I/O throughput timeline"
              />
            </article>
            <article class="nv-card resource-panel resource-panel--wide">
              <h4>CPU and memory pressure</h4>
              <p>Linux PSI avg10 percentages from producer-marked current cgroup scopes.</p>
              <ResourceTimelineChart
                :points="analysis.samples"
                :series="pressureSeries"
                y-axis-title="Stall time (%)"
                value-suffix="%"
                accessibility-label="CPU and memory pressure stall timeline"
              />
            </article>
            <article class="nv-card resource-panel resource-panel--wide">
              <h4>Runtime cardinality and faults</h4>
              <p>PID use and limit, process threads, open file descriptors, and cumulative major faults.</p>
              <ResourceTimelineChart
                :points="analysis.samples"
                :series="diagnosticSeries"
                y-axis-title="Count"
                accessibility-label="Runtime task, descriptor, and major-fault timeline"
              />
            </article>
            <article class="nv-card resource-panel">
              <h4>cgroup event counters</h4>
              <p>Cumulative kernel counters remain unavailable when the producer could not read the associated cgroup file.</p>
              <ResourceTimelineChart
                :points="analysis.samples"
                :series="cgroupEventSeries"
                y-axis-title="Cumulative event count"
                accessibility-label="cgroup throttle and memory-event count timeline"
              />
            </article>
            <article class="nv-card resource-panel">
              <h4>cgroup throttled time</h4>
              <p>Cumulative CPU time denied by cgroup throttling, kept separate from event counts.</p>
              <ResourceTimelineChart
                :points="analysis.samples"
                :series="cgroupThrottleTimeSeries"
                y-axis-title="Cumulative seconds"
                value-suffix="s"
                accessibility-label="cgroup throttled-time timeline"
              />
            </article>
          </div>
        </section>

        <section id="request-capture" class="resource-section">
          <h3 class="nv-section-title">Request capture pool</h3>
          <EmptyState
            v-if="!analysis.requestCapture"
            icon="data"
            title="Request capture evidence unavailable"
            description="This run predates request-capture component telemetry or did not create the run-owned capture pool. Other resource telemetry remains valid."
          />
          <template v-else>
            <div class="resource-kpis concurrency-kpis">
              <StatCard
                label="Capture workers"
                :value="formatMaybeInteger(analysis.requestCapture.workerCount)"
                :subtitle="`Artifact status: ${analysis.requestCapture.status}`"
              />
              <StatCard
                label="Capture calls"
                :value="`${formatMaybeInteger(analysis.requestCapture.callsCompleted)} / ${formatMaybeInteger(analysis.requestCapture.callsEnqueued)}`"
                subtitle="Completed / enqueued"
                color="blue"
              />
              <StatCard
                label="Peak active workers"
                :value="formatMaybeInteger(analysis.requestCapture.peakActiveWorkers)"
                :subtitle="`${formatMaybeInteger(analysis.requestCapture.peakQueuedCalls)} peak queued calls`"
                color="orange"
              />
              <StatCard
                label="Maximum queue wait"
                :value="formatMaybeDuration(analysis.requestCapture.queueWaitSecondsMax)"
                :subtitle="`${formatMaybeDuration(analysis.requestCapture.queueWaitSecondsAverage)} average`"
                color="orange"
              />
              <StatCard
                label="Queued utilization"
                :value="formatRatioPercent(analysis.requestCapture.utilizationWhileQueuedRatio)"
                :subtitle="`${formatRatioPercent(analysis.requestCapture.saturationWhileQueuedRatio)} of queued time saturated`"
                color="blue"
              />
              <StatCard
                label="Overall pool utilization"
                :value="formatRatioPercent(analysis.requestCapture.workerUtilizationRatio)"
                :subtitle="`${formatMaybeDuration(analysis.requestCapture.workerSecondsTotal)} aggregate worker time`"
                color="purple"
              />
              <StatCard
                label="Capture failures"
                :value="formatMaybeInteger(analysis.requestCapture.workerFailures)"
                :subtitle="`${formatMaybeInteger(analysis.requestCapture.abandonedBeforeSubmission)} abandoned before submission`"
              />
            </div>

            <NvCallout variant="info" title="How to read capture scaling" class="resource-warning">
              Capture workers perform local response sanitization, verification, and durable publication; they do not admit more requests to a DUT. Peak and queue totals are event-driven and exact within the run. The timeline is sampled with resource monitoring, so it can miss brief bursts while the aggregate cards retain their peaks.
            </NvCallout>

            <div class="resource-chart-grid">
              <article class="nv-card resource-panel concurrency-chart-panel">
                <h4>Worker use and waiting callers</h4>
                <p>Active local capture workers and callers waiting for a worker are shown against the configured pool size.</p>
                <ResourceTimelineChart
                  :points="analysis.samples"
                  :series="capturePoolSeries"
                  y-axis-title="Count"
                  accessibility-label="Request capture worker and queue timeline"
                />
              </article>
              <article class="nv-card resource-panel concurrency-chart-panel">
                <h4>Queued efficiency</h4>
                <p>Cumulative active-worker utilization and full-pool saturation while callers were queued.</p>
                <ResourceTimelineChart
                  :points="analysis.samples"
                  :series="captureEfficiencySeries"
                  y-axis-title="Percent"
                  value-suffix="%"
                  accessibility-label="Request capture queued utilization and saturation timeline"
                />
              </article>
            </div>

            <div class="resource-diagnostics concurrency-policy">
              <HealthDatum label="Observation interval" :value="formatMaybeDuration(analysis.requestCapture.observationSeconds)" />
              <HealthDatum label="Total queue wait" :value="formatMaybeDuration(analysis.requestCapture.queueWaitSecondsTotal)" />
              <HealthDatum label="Queued demand time" :value="formatMaybeDuration(analysis.requestCapture.queuedWallSeconds)" />
              <HealthDatum label="Queued capacity" :value="formatMaybeWorkerSeconds(analysis.requestCapture.queuedCapacityWorkerSeconds)" />
              <HealthDatum label="Queued active work" :value="formatMaybeWorkerSeconds(analysis.requestCapture.queuedActiveWorkerSeconds)" />
              <HealthDatum label="Runnable local gap" :value="formatMaybeWorkerSeconds(analysis.requestCapture.runnableGapWorkerSeconds)" />
              <HealthDatum label="Full-pool queued time" :value="formatMaybeDuration(analysis.requestCapture.saturatedWhileQueuedSeconds)" />
            </div>
          </template>
        </section>

        <section id="adaptive-concurrency" class="resource-section">
          <h3 class="nv-section-title">Concurrency scheduler</h3>
          <EmptyState
            v-if="concurrencyMissing"
            icon="data"
            title="Concurrency evidence unavailable"
            description="This run predates .metadata/concurrency_scheduler.json or did not enter the collector-execution scheduler. Resource telemetry above remains valid."
          />
          <NvCallout
            v-else-if="concurrencyLoadError"
            variant="warning"
            title="Concurrency evidence could not be loaded"
          >
            {{ concurrencyLoadError }}
          </NvCallout>
          <template v-else-if="concurrencyAnalysis">
            <div class="resource-kpis concurrency-kpis">
              <StatCard
                label="Scheduler mode"
                :value="concurrencyAnalysis.mode"
                :subtitle="`Artifact status: ${concurrencyAnalysis.status}`"
              />
              <StatCard
                label="Capacity"
                :value="`${concurrencyAnalysis.initialLimit} → ${concurrencyAnalysis.finalLimit}`"
                :subtitle="`Allowed range ${concurrencyAnalysis.minimumLimit}–${concurrencyAnalysis.maximumLimit}`"
                color="purple"
              />
              <StatCard
                label="Collector operations"
                :value="`${formatInteger(concurrencyAnalysis.completedOperations)} / ${formatInteger(concurrencyAnalysis.plannedOperations)}`"
                :subtitle="formatCompletionPercent(concurrencyAnalysis.completionPercent)"
                color="blue"
              />
              <StatCard
                label="Peak active"
                :value="formatInteger(concurrencyAnalysis.peakActiveOperations)"
                :subtitle="`${formatInteger(concurrencyAnalysis.peakActiveWeight)} peak active weight`"
                color="orange"
              />
              <StatCard
                label="Queued utilization"
                :value="formatRatioPercent(concurrencyAnalysis.utilizationWhileQueuedRatio)"
                :subtitle="queuedUtilizationSubtitle(concurrencyAnalysis.saturationWhileQueuedRatio, concurrencyAnalysis.queuedWallSeconds)"
                color="blue"
              />
              <StatCard
                label="Opportunistic backfill"
                :value="formatMaybeInteger(concurrencyAnalysis.backfilledOperations)"
                :subtitle="`${formatMaybeInteger(concurrencyAnalysis.peakQueuedOperations)} peak globally queued`"
                color="purple"
              />
              <StatCard
                label="Maximum queue wait"
                :value="formatDuration(concurrencyAnalysis.queueWaitSecondsMax)"
                :subtitle="`${formatDuration(concurrencyAnalysis.queueWaitSecondsAverage)} average`"
                color="orange"
              />
              <StatCard
                label="Decisions retained"
                :value="`${formatInteger(concurrencyAnalysis.decisionRetained)} / ${formatInteger(concurrencyAnalysis.decisionTotal)}`"
                :subtitle="`${formatInteger(concurrencyAnalysis.decisionDropped)} producer-dropped`"
              />
            </div>

            <NvCallout variant="info" title="How to read this timeline" class="resource-warning">
              Capacity is the global weighted collector-operation budget. Schema 1.2 records periodic progress in every mode plus event-driven queued-utilization totals; schema 1.1 records progress only at scheduler decisions. Runnable idle capacity means a queued operation could have fit and is avoidable. Weight fragmentation means no queued operation fit the remaining weighted capacity. Per-DUT endpoint serialization and tail ordering happen before global admission and are intentionally excluded. Elapsed time is relative to scheduler startup and may have a different origin from the resource timelines above.
            </NvCallout>
            <NvCallout
              v-for="warning in concurrencyAnalysis.warnings"
              :key="warning"
              variant="warning"
              title="Scheduler evidence health"
              class="resource-warning"
            >
              {{ warning }}
            </NvCallout>

            <article class="nv-card resource-panel concurrency-chart-panel">
              <h4>Capacity and completion progress</h4>
              <p>Markers include periodic fixed/conservative observations and adaptive decisions. Hover a point to inspect its governed reason code.</p>
              <ConcurrencyTimelineChart
                :points="concurrencyAnalysis.decisions"
                :planned-operations="concurrencyAnalysis.plannedOperations"
              />
            </article>

            <div class="resource-diagnostics concurrency-policy">
              <HealthDatum label="DUTs" :value="formatInteger(concurrencyAnalysis.dutCount)" />
              <HealthDatum label="Service lanes" :value="formatInteger(concurrencyAnalysis.serviceLaneCount)" />
              <HealthDatum label="Weighted demand" :value="formatInteger(concurrencyAnalysis.weightedDemand)" />
              <HealthDatum label="Skipped operations" :value="formatInteger(concurrencyAnalysis.skippedOperations)" />
              <HealthDatum label="Sample interval" :value="formatMaybeDuration(concurrencyAnalysis.sampleIntervalSeconds)" />
              <HealthDatum label="Healthy windows" :value="formatMaybeInteger(concurrencyAnalysis.healthyWindowsRequired)" />
              <HealthDatum label="Increase step ceiling" :value="formatMaybeInteger(concurrencyAnalysis.increaseStep)" />
              <HealthDatum label="Cooldown" :value="formatMaybeDuration(concurrencyAnalysis.cooldownSeconds)" />
              <HealthDatum label="Endpoint cooldown" :value="formatMaybeDuration(concurrencyAnalysis.endpointCooldownSeconds)" />
              <HealthDatum label="Per-DUT Redfish" :value="formatMaybeInteger(concurrencyAnalysis.perDutRedfishLimit)" />
              <HealthDatum label="Queued at snapshot" :value="formatInteger(concurrencyAnalysis.currentQueuedOperations)" />
              <HealthDatum label="Queued demand time" :value="formatMaybeDuration(concurrencyAnalysis.queuedWallSeconds)" />
              <HealthDatum label="Full-capacity queued time" :value="formatMaybeDuration(concurrencyAnalysis.saturatedWhileQueuedSeconds)" />
              <HealthDatum label="Runnable idle capacity" :value="formatMaybeWeightSeconds(concurrencyAnalysis.runnableGapWeightSeconds)" />
              <HealthDatum label="Weight fragmentation" :value="formatMaybeWeightSeconds(concurrencyAnalysis.fragmentationWeightSeconds)" />
              <HealthDatum label="Admissions" :value="formatInteger(concurrencyAnalysis.admissions)" />
              <HealthDatum label="Scheduler started" :value="formatTimestamp(concurrencyAnalysis.startedAt)" />
              <HealthDatum label="Scheduler completed" :value="formatTimestamp(concurrencyAnalysis.completedAt)" />
            </div>

            <div class="nv-table-viewport concurrency-table-wrap">
              <table class="nv-table concurrency-table">
                <caption>Most recent browser-retained observations and the pressure signals available to the controller</caption>
                <thead>
                  <tr>
                    <th scope="col">Elapsed</th>
                    <th scope="col">Action</th>
                    <th scope="col">Capacity</th>
                    <th scope="col">Reason</th>
                    <th scope="col">Active</th>
                    <th scope="col">Queued</th>
                    <th scope="col">Completed window</th>
                    <th scope="col">CPU</th>
                    <th scope="col">Memory headroom</th>
                    <th scope="col">Event-loop lag</th>
                    <th scope="col">Remote events</th>
                    <th scope="col">Transport p95</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(decision, index) in displayedConcurrencyDecisions" :key="`${decision.elapsedSeconds}-${index}`">
                    <td>{{ formatDuration(decision.elapsedSeconds) }}</td>
                    <td><span :class="['concurrency-action', `concurrency-action--${decision.action}`]">{{ decision.action }}</span></td>
                    <td><code>{{ decision.previousLimit }} → {{ decision.newLimit }}</code></td>
                    <td>{{ formatReasons(decision.reasons) }}</td>
                    <td>{{ formatMaybeInteger(decision.progress?.activeOperations ?? null) }}</td>
                    <td>{{ formatMaybeInteger(decision.progress?.queuedOperations ?? null) }}</td>
                    <td>{{ formatMaybeInteger(decision.signals?.completedOperations ?? null) }}</td>
                    <td>{{ formatRatioPercent(decision.signals?.cpuUtilization ?? null) }}</td>
                    <td>{{ formatRatioPercent(decision.signals?.memoryHeadroomRatio ?? null) }}</td>
                    <td>{{ formatMaybeDuration(decision.signals?.eventLoopLagSeconds ?? null) }}</td>
                    <td>{{ formatInteger(sumCounts(decision.signals?.remoteEvents ?? {})) }}</td>
                    <td>{{ formatMaybeDuration(decision.signals?.transportLatencyP95Seconds ?? null) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div v-if="concurrencyAnalysis.serviceMetrics.length" class="nv-table-viewport concurrency-table-wrap">
              <table class="nv-table concurrency-table">
                <caption>Aggregate admission activity by sanitized service lane</caption>
                <thead><tr><th scope="col">Service</th><th scope="col">Completed</th><th scope="col">Peak active</th><th scope="col">Active total</th><th scope="col">Active average</th></tr></thead>
                <tbody>
                  <tr v-for="service in concurrencyAnalysis.serviceMetrics" :key="service.service">
                    <td><strong>{{ service.service }}</strong></td>
                    <td>{{ formatInteger(service.completedOperations) }}</td>
                    <td>{{ formatInteger(service.peakActiveOperations) }}</td>
                    <td>{{ formatDuration(service.activeSecondsTotal) }}</td>
                    <td>{{ formatDuration(service.activeSecondsAverage) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div v-if="concurrencyEventCounts.length" class="concurrency-events" aria-label="Scheduler pressure and endpoint cooldown counters">
              <span v-for="event in concurrencyEventCounts" :key="event.label" class="concurrency-event">
                {{ event.label }}: <strong>{{ formatInteger(event.count) }}</strong>
              </span>
            </div>
          </template>
        </section>

        <section id="health" class="resource-section">
          <h3 class="nv-section-title">Sample and data health</h3>
          <div class="resource-health-grid">
            <HealthDatum label="Producer status" :value="analysis.health.status" />
            <HealthDatum label="Samples loaded" :value="String(analysis.health.samplesLoaded)" />
            <HealthDatum label="Samples reported" :value="formatMaybeInteger(analysis.health.samplesReported)" />
            <HealthDatum label="Samples retained" :value="formatMaybeInteger(analysis.health.samplesRetained)" />
            <HealthDatum label="Retained-file coverage" :value="formatMaybeNumber(analysis.health.retainedFileCoveragePercent, '%')" />
            <HealthDatum label="Cadence coverage" :value="formatMaybeNumber(analysis.health.cadenceCoveragePercent, '%')" />
            <HealthDatum label="Periodic samples" :value="formatMaybeInteger(analysis.health.scheduledPeriodicSamples)" />
            <HealthDatum label="Missed deadlines" :value="formatMaybeInteger(analysis.health.missedScheduledIntervals)" />
            <HealthDatum label="Max start jitter" :value="formatMaybeNumber(analysis.health.maxSamplingJitterSeconds, 's')" />
            <HealthDatum label="Expected interval" :value="formatMaybeNumber(analysis.health.expectedIntervalSeconds, 's')" />
            <HealthDatum label="Gaps" :value="String(analysis.health.gapCount)" />
            <HealthDatum label="Estimated missing" :value="String(analysis.health.estimatedMissingSamples)" />
            <HealthDatum label="Rotations" :value="formatMaybeInteger(analysis.health.rotations)" />
            <HealthDatum label="Rotated out" :value="formatMaybeInteger(analysis.health.samplesRotatedOut)" />
            <HealthDatum label="Producer dropped" :value="formatMaybeInteger(analysis.health.samplesDropped)" />
            <HealthDatum label="Malformed skipped" :value="String(analysis.health.malformedLines)" />
            <HealthDatum label="Oversized skipped" :value="String(analysis.health.oversizedLines)" />
            <HealthDatum label="Segments ignored" :value="String(analysis.health.historySegmentsIgnored)" />
            <HealthDatum label="Counter resets" :value="String(analysis.health.counterResets)" />
            <HealthDatum label="Write failures" :value="formatMaybeInteger(analysis.health.sampleWriteFailures)" />
            <HealthDatum label="Final summary write" :value="formatMaybeBoolean(analysis.health.artifactWriteSucceeded)" />
          </div>
          <p class="resource-footnote">
            Retained-file coverage measures declared retained samples loaded from disk. Cadence coverage measures periodic samples started versus monotonic deadlines missed by the producer. The browser applies fixed byte, line, and sample caps before bounded timeline downsampling.
          </p>
        </section>

        <section id="cgroup" class="resource-section">
          <h3 class="nv-section-title">cgroup diagnostics</h3>
          <div v-if="analysis.scopes.length" class="nv-table-viewport">
            <table class="nv-table">
              <caption>Current and ancestor cgroup scope diagnostics</caption>
              <thead>
                <tr>
                  <th scope="col">Scope</th><th scope="col">Memory</th><th scope="col">Memory limit</th><th scope="col">Swap</th><th scope="col">CPU</th><th scope="col">Throttle</th><th scope="col">OOM / kills</th><th scope="col">PSI CPU / memory</th><th scope="col">PIDs</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(scope, scopeIndex) in analysis.scopes" :key="scope.id">
                  <td><strong>{{ scope.controller }}</strong> · {{ scope.role }}<br><small>scope {{ scopeIndex + 1 }}</small></td>
                  <td>
                    {{ formatMaybeBytes(scope.memoryCurrentBytes) }}
                    <br><small>observed peak {{ formatMaybeBytes(scope.memoryPeakBytes) }}</small>
                    <br><small>kernel lifetime HWM {{ formatMaybeBytes(scope.memoryLifetimePeakBytes) }}</small>
                  </td>
                  <td>{{ formatLimit(scope.memoryLimitBytes, scope.memoryLimitState) }}</td>
                  <td>
                    {{ formatMaybeBytes(scope.swapCurrentBytes) }}
                    <br><small>{{ swapSemanticsLabel(scope.swapCurrentSemantics) }}</small>
                    <br><small>run-observed peak {{ formatMaybeBytes(scope.swapObservedPeakBytes) }}</small>
                    <br><small>kernel lifetime HWM {{ formatMaybeBytes(scope.swapLifetimeHighWaterBytes) }}</small>
                    <br><small>limit {{ formatLimit(scope.swapLimitBytes, scope.swapLimitState) }}, counter increments {{ formatMaybeInteger(scope.swapEvents) }}</small>
                    <br v-if="scope.memoryAndSwapCurrentBytes !== null"><small v-if="scope.memoryAndSwapCurrentBytes !== null">v1 memory+swap {{ formatMaybeBytes(scope.memoryAndSwapCurrentBytes) }} / {{ formatLimit(scope.memoryAndSwapLimitBytes, scope.memoryAndSwapLimitState) }}</small>
                  </td>
                  <td>{{ formatMaybeNumber(scope.cpuUsageSeconds, 's') }}</td>
                  <td>{{ formatMaybeInteger(scope.throttleEvents) }}<br><small>{{ formatMaybeNumber(scope.throttledSeconds, 's') }}</small></td>
                  <td>{{ formatMaybeInteger(scope.oomEvents) }} / {{ formatMaybeInteger(scope.oomKillEvents) }}<br><small>high {{ formatMaybeInteger(scope.memoryHighEvents) }}</small></td>
                  <td>{{ formatMaybeNumber(scope.cpuPressureSomeAvg10, '%') }} / {{ formatMaybeNumber(scope.memoryPressureSomeAvg10, '%') }}</td>
                  <td>{{ formatMaybeInteger(scope.pidsCurrent) }} / {{ formatLimit(scope.pidsLimit, scope.pidsLimitState, false) }}<br><small>max events {{ formatMaybeInteger(scope.pidsMaxEvents) }}</small></td>
                </tr>
              </tbody>
            </table>
          </div>
          <EmptyState v-else icon="data" title="cgroup metrics unavailable" description="The run did not record any cgroup scopes." />
        </section>

        <section id="scheduler" class="resource-section">
          <h3 class="nv-section-title">Scheduler and CPU budget</h3>
          <div class="resource-diagnostics">
            <HealthDatum v-for="entry in analysis.scheduler" :key="entry.label" :label="entry.label" :value="entry.value" />
          </div>
        </section>

        <section v-if="analysis.monitorErrors.length" id="monitor-errors" class="resource-section">
          <h3 class="nv-section-title">Monitor errors</h3>
          <NvCallout v-for="(error, index) in analysis.monitorErrors" :key="`${error.timestamp}-${index}`" variant="warning" title="Resource monitor diagnostic">
            {{ error.timestamp ?? 'Timestamp unavailable' }} — {{ error.code }}. Review the local runtime log and resource artifact for authorized diagnostic detail.
          </NvCallout>
        </section>

        <section id="definitions" class="resource-section">
          <NvCollapsibleSection v-model:collapsed="definitionsCollapsed" title="Metric definitions and producer scope" :badge="`${analysis.metricDefinitions.length} definitions`">
            <div class="nv-table-viewport">
              <table class="nv-table">
                <caption>Resource metric definitions and sources</caption>
                <thead><tr><th scope="col">Metric</th><th scope="col">Definition</th><th scope="col">Source</th></tr></thead>
                <tbody>
                  <tr v-for="definition in analysis.metricDefinitions" :key="definition.metric">
                    <td><strong>{{ definition.metric }}</strong></td>
                    <td>{{ definition.definition }}</td>
                    <td><code>{{ definition.source }}</code></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </NvCollapsibleSection>
        </section>
      </template>
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onBeforeUnmount, ref, watch } from 'vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import EmptyState from '@/components/common/EmptyState.vue'
import NvCallout from '@/components/common/NvCallout.vue'
import NvCollapsibleSection from '@/components/common/NvCollapsibleSection.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import ConcurrencyTimelineChart from '@/components/charts/ConcurrencyTimelineChart.vue'
import ResourceTimelineChart from '@/components/charts/ResourceTimelineChart.vue'
import StatCard from '@/components/dashboard/StatCard.vue'
import {
  ConcurrencySchedulerArtifactMissingError,
  loadConcurrencySchedulerArtifact,
} from '@/services/concurrencySchedulerLoader'
import {
  ResourceArtifactMissingError,
  loadResourceUsageArtifacts,
} from '@/services/resourceUsageLoader'
import { useFileSystemStore } from '@/stores/fileSystem'
import type { ConcurrencySchedulerAnalysis } from '@/types/concurrencyScheduler'
import type {
  ResourceHealthState,
  ResourceLimitState,
  ResourceSamplePoint,
  ResourceScopeDiagnostic,
  ResourceSignalState,
  ResourceUsageAnalysis,
} from '@/types/resourceUsage'
import { analyzeResourceUsage } from '@/utils/resourceUsage'
import { analyzeConcurrencyScheduler } from '@/utils/concurrencyScheduler'

const KIB = 1024
const MIB = 1024 * 1024

const anchors = [
  { id: 'overview', label: 'Overview' },
  { id: 'signals', label: 'Run Signals' },
  { id: 'timelines', label: 'Timelines' },
  { id: 'request-capture', label: 'Capture Pool' },
  { id: 'adaptive-concurrency', label: 'Concurrency Scheduler' },
  { id: 'health', label: 'Data Health' },
  { id: 'cgroup', label: 'cgroup' },
  { id: 'scheduler', label: 'Scheduler' },
  { id: 'definitions', label: 'Definitions' },
]

const HealthDatum = defineComponent({
  props: { label: { type: String, required: true }, value: { type: String, required: true } },
  setup(props) {
    return () => h('div', { class: 'resource-datum' }, [
      h('span', { class: 'resource-datum__label' }, props.label),
      h('strong', { class: props.value === 'Unavailable' ? 'resource-datum__value resource-datum__value--missing' : 'resource-datum__value' }, props.value),
    ])
  },
})

const fileSystemStore = useFileSystemStore()
const analysis = ref<ResourceUsageAnalysis | null>(null)
const concurrencyAnalysis = ref<ConcurrencySchedulerAnalysis | null>(null)
const loading = ref(false)
const missing = ref(false)
const loadError = ref<string | null>(null)
const concurrencyMissing = ref(false)
const concurrencyLoadError = ref<string | null>(null)
const definitionsCollapsed = ref(true)
let loadGeneration = 0
let activeLoadController: AbortController | null = null

const waitingForDirectory = computed(() => fileSystemStore.mode === 'file' && !fileSystemStore.directoryLoaded)
const measurementScopeDescription = computed(() => {
  if (analysis.value?.producerScope === 'post_logger_start_through_pre_logger_finalization') {
    return 'Monitoring starts after runtime logging is available and ends during cleanup before runtime logging is finalized. Collection and cleanup work inside that interval is included; later interactive report generation, archive creation, upload, and extraction are outside this artifact.'
  }
  if (analysis.value?.producerScope === 'collection_and_pre_packaging_cleanup') {
    return 'Monitoring covers the collection workflow and cleanup before report packaging. The artifact does not establish coverage for later interactive report generation, archive creation, upload, or extraction.'
  }
  return 'This artifact contains resource samples for the lifecycle interval selected by its producer. Exact lifecycle boundaries are unavailable; later report generation, archive creation, upload, and extraction must not be inferred from it.'
})
const cpuBudgetSubtitle = computed(() => analysis.value?.kpis.availableCpus === null
  ? 'Available CPU quota unavailable'
  : `of ${formatMaybeNumber(analysis.value?.kpis.availableCpus ?? null, ' cores')}`)

const signalCards = computed(() => {
  const signals = analysis.value?.signals
  if (!signals) return []
  return [
    {
      label: 'RSS accumulation',
      state: signals.memoryAccumulationState,
      value: signals.rssGrowthBytes === null
        ? 'Unavailable'
        : `${formatSignedBytes(signals.rssGrowthBytes)} (${formatSignedRate(signals.rssGrowthBytesPerHour)})`,
      detail: signals.peakRssRetainedPercent === null
        ? 'Baseline, final, or monitored-duration evidence is incomplete.'
        : `${formatMaybeNumber(signals.peakRssRetainedPercent, '%')} of peak RSS remained at the final sample. Growth is not proof of a leak.`,
    },
    {
      label: 'CPU pressure',
      state: signals.cpuPressureState,
      value: signals.peakCpuBudgetPercent === null
        ? 'Budget peak unavailable'
        : `${formatMaybeNumber(signals.peakCpuBudgetPercent, '%')} peak budget use`,
      detail: `${formatMaybeInteger(signals.throttleEvents)} throttle events; ${formatMaybeNumber(signals.throttledSeconds, 's')} throttled; PSI some avg10 peak ${formatMaybeNumber(signals.peakCpuPressureSomeAvg10, '%')}.`,
    },
    {
      label: 'Memory pressure',
      state: signals.memoryPressureState,
      value: signals.peakMemoryLimitPercent === null
        ? 'Finite limit unavailable'
        : `${formatMaybeNumber(signals.peakMemoryLimitPercent, '%')} peak limit use`,
      detail: `${formatMaybeInteger(signals.memoryHighEvents)} high, ${formatMaybeInteger(signals.oomEvents)} OOM, ${formatMaybeInteger(signals.oomKillEvents)} OOM-kill events; PSI some avg10 peak ${formatMaybeNumber(signals.peakMemoryPressureSomeAvg10, '%')}.`,
    },
    {
      label: 'Swap activity',
      state: signals.swapState,
      value: signals.swapState === 'unavailable'
        ? 'Unavailable'
        : `${formatMaybeBytes(signals.processObservedPeakSwapBytes)} process / ${formatMaybeBytes(signals.cgroupObservedPeakSwapBytes)} current cgroup`,
      detail: signals.swapState === 'unavailable'
        ? 'This producer did not record process or cgroup swap; absence is not treated as zero.'
        : `Run-observed peak process and current-cgroup swap values; ${formatMaybeInteger(signals.swapEvents)} swap limit/failure counter increments.`,
    },
  ]
})

const memorySeries = [
  { key: 'rssBytes' as keyof ResourceSamplePoint, label: 'Process RSS', color: '#76b900' },
  { key: 'processSwapBytes' as keyof ResourceSamplePoint, label: 'Process swap', color: '#8c7cff' },
  { key: 'cgroupMemoryBytes' as keyof ResourceSamplePoint, label: 'Current cgroup memory', color: '#2ca8ff' },
  { key: 'cgroupSwapBytes' as keyof ResourceSamplePoint, label: 'Current cgroup swap', color: '#e26bb7' },
]
const cpuSeries = [
  { key: 'cpuCores' as keyof ResourceSamplePoint, label: 'Process + child CPU', color: '#76b900' },
  { key: 'cgroupCpuCores' as keyof ResourceSamplePoint, label: 'Current cgroup CPU', color: '#2ca8ff' },
  { key: 'availableCpus' as keyof ResourceSamplePoint, label: 'Available CPU budget', color: '#f5a623' },
]
const ioSeries = [
  { key: 'physicalReadBytesPerSecond' as keyof ResourceSamplePoint, label: 'Physical read', color: '#2ca8ff' },
  { key: 'physicalWriteBytesPerSecond' as keyof ResourceSamplePoint, label: 'Physical write', color: '#f5a623' },
  { key: 'logicalReadBytesPerSecond' as keyof ResourceSamplePoint, label: 'Logical read', color: '#8c7cff' },
  { key: 'logicalWriteBytesPerSecond' as keyof ResourceSamplePoint, label: 'Logical write', color: '#e26bb7' },
]
const pressureSeries = [
  { key: 'cpuPressureSomeAvg10' as keyof ResourceSamplePoint, label: 'CPU PSI some avg10', color: '#f5a623' },
  { key: 'cpuPressureFullAvg10' as keyof ResourceSamplePoint, label: 'CPU PSI full avg10', color: '#ef5350' },
  { key: 'memoryPressureSomeAvg10' as keyof ResourceSamplePoint, label: 'Memory PSI some avg10', color: '#e26bb7' },
  { key: 'memoryPressureFullAvg10' as keyof ResourceSamplePoint, label: 'Memory PSI full avg10', color: '#8c7cff' },
]
const diagnosticSeries = [
  { key: 'pidsCurrent' as keyof ResourceSamplePoint, label: 'PIDs', color: '#2ca8ff' },
  { key: 'pidsLimit' as keyof ResourceSamplePoint, label: 'PID limit', color: '#ef5350' },
  { key: 'threads' as keyof ResourceSamplePoint, label: 'Threads', color: '#76b900' },
  { key: 'openFds' as keyof ResourceSamplePoint, label: 'Open FDs', color: '#8c7cff' },
  { key: 'majorPageFaults' as keyof ResourceSamplePoint, label: 'Major faults (cumulative)', color: '#ef5350' },
]
const cgroupEventSeries = [
  { key: 'throttleEvents' as keyof ResourceSamplePoint, label: 'Throttle events', color: '#f5a623' },
  { key: 'memoryHighEvents' as keyof ResourceSamplePoint, label: 'Memory high events', color: '#8c7cff' },
  { key: 'oomEvents' as keyof ResourceSamplePoint, label: 'OOM events', color: '#e26bb7' },
  { key: 'oomKillEvents' as keyof ResourceSamplePoint, label: 'OOM kill events', color: '#dc3545' },
  { key: 'swapEvents' as keyof ResourceSamplePoint, label: 'Swap counter increments', color: '#2ca8ff' },
]
const cgroupThrottleTimeSeries = [
  { key: 'throttledSeconds' as keyof ResourceSamplePoint, label: 'Throttled time', color: '#ef5350' },
]
const capturePoolSeries = [
  { key: 'captureWorkerCount' as keyof ResourceSamplePoint, label: 'Worker capacity', color: '#8c7cff' },
  { key: 'captureActiveWorkers' as keyof ResourceSamplePoint, label: 'Active workers', color: '#76b900' },
  { key: 'captureQueuedCalls' as keyof ResourceSamplePoint, label: 'Queued callers', color: '#f5a623' },
]
const captureEfficiencySeries = [
  { key: 'captureUtilizationWhileQueuedPercent' as keyof ResourceSamplePoint, label: 'Queued utilization', color: '#2ca8ff' },
  { key: 'captureSaturationWhileQueuedPercent' as keyof ResourceSamplePoint, label: 'Queued saturation', color: '#ef5350' },
]

const displayedConcurrencyDecisions = computed(() => concurrencyAnalysis.value?.decisions.slice(-100) ?? [])
const concurrencyEventCounts = computed(() => {
  if (!concurrencyAnalysis.value) return []
  return [
    ...concurrencyAnalysis.value.remotePressureEvents.map(event => ({ ...event, label: `pressure · ${event.label}` })),
    ...concurrencyAnalysis.value.endpointCooldowns.map(event => ({ ...event, label: `cooldown · ${event.label}` })),
  ]
})

async function loadResources(signal?: AbortSignal) {
  const generation = ++loadGeneration
  analysis.value = null
  concurrencyAnalysis.value = null
  missing.value = false
  loadError.value = null
  concurrencyMissing.value = false
  concurrencyLoadError.value = null
  if (waitingForDirectory.value) {
    loading.value = false
    return
  }
  loading.value = true
  const access = {
    mode: fileSystemStore.mode,
    fileMap: fileSystemStore.fileMap,
    signal,
  }
  const [resourceResult, concurrencyResult] = await Promise.allSettled([
    loadResourceUsageArtifacts(access),
    loadConcurrencySchedulerArtifact(access),
  ])
  if (signal?.aborted || generation !== loadGeneration) return

  if (resourceResult.status === 'fulfilled') {
    analysis.value = analyzeResourceUsage({
      artifact: resourceResult.value.artifact,
      samples: resourceResult.value.samples,
      diagnostics: resourceResult.value.diagnostics,
    })
  } else if (resourceResult.reason instanceof ResourceArtifactMissingError) {
    missing.value = true
  } else {
    loadError.value = resourceResult.reason instanceof Error
      ? resourceResult.reason.message
      : String(resourceResult.reason)
  }

  if (concurrencyResult.status === 'fulfilled') {
    concurrencyAnalysis.value = analyzeConcurrencyScheduler(concurrencyResult.value)
  } else if (concurrencyResult.reason instanceof ConcurrencySchedulerArtifactMissingError) {
    concurrencyMissing.value = true
  } else {
    concurrencyLoadError.value = concurrencyResult.reason instanceof Error
      ? concurrencyResult.reason.message
      : String(concurrencyResult.reason)
  }
  loading.value = false
}

function startResourceLoad() {
  activeLoadController?.abort()
  const controller = new AbortController()
  activeLoadController = controller
  void loadResources(controller.signal).finally(() => {
    if (activeLoadController === controller) activeLoadController = null
  })
}

watch(
  [() => fileSystemStore.mode, () => fileSystemStore.directoryLoaded],
  startResourceLoad,
  { immediate: true },
)

onBeforeUnmount(() => {
  loadGeneration++
  activeLoadController?.abort()
  activeLoadController = null
})

function scrollToSection(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function formatMaybeBytes(value: number | null): string {
  return value === null ? 'Unavailable' : formatIecBytes(value)
}

function formatIecBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return 'Unavailable'
  if (value < KIB) return `${Math.round(value)} B`
  if (value < MIB) return `${(value / KIB).toFixed(1)} KiB`
  if (value < 1024 * MIB) return `${(value / MIB).toFixed(1)} MiB`
  return `${(value / (1024 * MIB)).toFixed(1)} GiB`
}

function formatMaybeNumber(value: number | null, suffix: string): string {
  if (value === null || !Number.isFinite(value)) return 'Unavailable'
  const precision = Math.abs(value) < 10 && value !== 0 ? 2 : 1
  return `${value.toFixed(precision)}${suffix}`
}

function formatMaybeInteger(value: number | null): string {
  return value === null ? 'Unavailable' : Math.round(value).toLocaleString()
}

function formatMaybeBoolean(value: boolean | null): string {
  return value === null ? 'Unavailable' : value ? 'Succeeded' : 'Failed'
}

function formatInteger(value: number): string {
  return Math.round(value).toLocaleString()
}

function formatDuration(value: number): string {
  if (!Number.isFinite(value) || value < 0) return 'Unavailable'
  if (value < 1) return `${(value * 1000).toFixed(value < 0.01 ? 1 : 0)} ms`
  if (value < 60) return `${value.toFixed(value < 10 ? 2 : 1)}s`
  if (value < 3600) return `${(value / 60).toFixed(1)}m`
  return `${(value / 3600).toFixed(2)}h`
}

function formatMaybeDuration(value: number | null): string {
  return value === null ? 'Unavailable' : formatDuration(value)
}

function formatMaybeWeightSeconds(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return 'Unavailable'
  return `${value.toLocaleString(undefined, { maximumFractionDigits: 2 })} weight·s`
}

function formatMaybeWorkerSeconds(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return 'Unavailable'
  return `${value.toLocaleString(undefined, { maximumFractionDigits: 2 })} worker·s`
}

function formatTimestamp(value: string | null): string {
  return value === null ? 'Unavailable' : new Date(value).toLocaleString()
}

function formatRatioPercent(value: number | null): string {
  return value === null ? 'Unavailable' : `${(value * 100).toFixed(value < 0.1 ? 2 : 1)}%`
}

function queuedUtilizationSubtitle(saturation: number | null, queuedWallSeconds: number | null): string {
  if (saturation !== null) return `${formatRatioPercent(saturation)} of queued time at full capacity`
  return queuedWallSeconds === 0
    ? 'No globally queued demand recorded'
    : 'Not recorded by this artifact schema'
}

function formatCompletionPercent(value: number | null): string {
  return value === null ? 'Planned operation count unavailable' : `${value.toFixed(1)}% of planned operations`
}

function formatReasons(reasons: string[]): string {
  return reasons.length > 0 ? reasons.map(reason => reason.replace(/_/g, ' ')).join(', ') : 'Not recorded'
}

function sumCounts(values: Record<string, number>): number {
  return Object.values(values).reduce((total, value) => total + value, 0)
}

function formatSignedBytes(value: number): string {
  if (value === 0) return '0 B'
  return `${value > 0 ? '+' : '−'}${formatIecBytes(Math.abs(value))}`
}

function formatSignedRate(value: number | null): string {
  return value === null ? 'rate unavailable' : `${formatSignedBytes(value)}/h`
}

function formatLimit(value: number | null, state: ResourceLimitState, bytes = true): string {
  if (state === 'unlimited') return 'Unlimited'
  if (state === 'unavailable' || value === null) return 'Unavailable'
  return bytes ? formatIecBytes(value) : Math.round(value).toLocaleString()
}

function healthLabel(state: ResourceHealthState): string {
  return state.charAt(0).toUpperCase() + state.slice(1)
}

function signalStateLabel(state: ResourceSignalState): string {
  return state === 'clear' ? 'No signal' : state === 'observed' ? 'Observed' : state === 'critical' ? 'Critical' : 'Unavailable'
}

function swapSemanticsLabel(semantics: ResourceScopeDiagnostic['swapCurrentSemantics']): string {
  if (semantics === 'direct') return 'direct swap counter'
  if (semantics === 'derived_memsw') return 'derived from cgroup v1 memory+swap minus memory'
  return 'swap accounting unavailable'
}
</script>

<style scoped>
.resource-layout { min-height: calc(100vh - 88px); }
.resource-sidebar__divider { border-top: 1px solid var(--nv-glass-border); margin: 6px 0; }
.resource-sidebar__title { padding: 8px 12px; margin: 0; font-size: 0.6875rem; }
.resource-sidebar__link { font-size: 0.6875rem; }
.resource-page { margin-left: 260px; }
.resource-heading { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin: 12px 0 16px; }
.resource-heading h2 { margin: 0 0 4px; }
.resource-heading p, .resource-panel p, .resource-footnote { margin: 0; color: var(--nv-text-tertiary); font-size: 0.75rem; }
.resource-health { border-radius: 999px; padding: 5px 10px; font-size: 0.6875rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; }
.resource-health--healthy { background: color-mix(in srgb, var(--nv-success) 15%, transparent); color: var(--nv-success); }
.resource-health--degraded { background: color-mix(in srgb, var(--nv-warning) 15%, transparent); color: var(--nv-warning); }
.resource-health--limited { background: color-mix(in srgb, var(--nv-info) 15%, transparent); color: var(--nv-info); }
.resource-health--unavailable { background: var(--nv-glass-bg-light); color: var(--nv-text-tertiary); }
.resource-section { scroll-margin-top: 72px; margin-top: 24px; }
.resource-section > .nv-section-title { margin: 0 0 12px; }
.resource-kpis { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
.resource-signal-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.resource-signal { border-left: 3px solid var(--nv-text-tertiary); }
.resource-signal--clear { border-left-color: var(--nv-success); }
.resource-signal--observed { border-left-color: var(--nv-warning); }
.resource-signal--critical { border-left-color: var(--nv-error); }
.resource-signal__heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.resource-signal__heading h4 { margin: 0; font-size: 0.8125rem; }
.resource-signal__heading span { color: var(--nv-text-tertiary); font-size: 0.625rem; font-weight: 700; text-transform: uppercase; }
.resource-signal > strong { display: block; margin-top: 10px; color: var(--nv-text-primary); font-family: var(--nv-font-mono); font-size: 0.875rem; }
.resource-signal > p { margin: 6px 0 0; color: var(--nv-text-tertiary); font-size: 0.6875rem; }
.resource-warning { margin-top: 10px; }
.resource-chart-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.resource-panel { min-width: 0; }
.resource-panel--wide { grid-column: span 2; }
.resource-panel h4 { margin: 0 0 4px; font-size: 0.8125rem; }
.concurrency-kpis { margin-bottom: 14px; }
.concurrency-chart-panel { margin-top: 14px; }
.concurrency-policy { margin-top: 14px; }
.concurrency-table-wrap { margin-top: 14px; }
.concurrency-table td { vertical-align: top; }
.concurrency-action { display: inline-flex; border-radius: 999px; padding: 2px 7px; background: var(--nv-glass-bg-light); color: var(--nv-text-secondary); font-size: 0.625rem; font-weight: 700; text-transform: uppercase; }
.concurrency-action--increase { background: color-mix(in srgb, var(--nv-success) 15%, transparent); color: var(--nv-success); }
.concurrency-action--decrease { background: color-mix(in srgb, var(--nv-error) 15%, transparent); color: var(--nv-error); }
.concurrency-action--start, .concurrency-action--stop { background: color-mix(in srgb, var(--nv-info) 15%, transparent); color: var(--nv-info); }
.concurrency-events { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
.concurrency-event { border: 1px solid var(--nv-glass-border); border-radius: 999px; padding: 5px 9px; color: var(--nv-text-secondary); font-size: 0.6875rem; }
.resource-health-grid, .resource-diagnostics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; }
:deep(.resource-datum) { display: flex; flex-direction: column; min-width: 0; padding: 10px 12px; border: 1px solid var(--nv-glass-border); border-radius: var(--nv-radius-md); background: var(--nv-glass-bg); }
:deep(.resource-datum__label) { color: var(--nv-text-tertiary); font-size: 0.625rem; text-transform: uppercase; letter-spacing: 0.03em; }
:deep(.resource-datum__value) { margin-top: 3px; color: var(--nv-text-primary); font-family: var(--nv-font-mono); font-size: 0.75rem; overflow-wrap: anywhere; }
:deep(.resource-datum__value--missing) { color: var(--nv-text-tertiary); font-style: italic; font-weight: 500; }
.resource-footnote { margin-top: 10px; }
caption { padding: 8px 10px; color: var(--nv-text-tertiary); font-size: 0.6875rem; text-align: left; }
code { color: var(--nv-text-secondary); font-family: var(--nv-font-mono); font-size: 0.6875rem; overflow-wrap: anywhere; }
small { color: var(--nv-text-tertiary); }
@media (max-width: 1023px) {
  .resource-sidebar { display: none; }
  .resource-page { margin-left: 0; }
  .resource-kpis, .resource-health-grid, .resource-diagnostics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 700px) {
  .resource-chart-grid { grid-template-columns: 1fr; }
  .resource-panel--wide { grid-column: auto; }
  .resource-kpis, .resource-signal-grid, .resource-health-grid, .resource-diagnostics { grid-template-columns: 1fr; }
}
</style>
