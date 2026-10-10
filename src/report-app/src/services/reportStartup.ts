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

const STAGE_LABELS = {
  reading: 'Reading report data…',
  decoding: 'Decoding embedded report…',
  decompressing: 'Decompressing report data…',
  parsing: 'Preparing report data…',
  validating: 'Checking report data…',
  rendering: 'Preparing report view…',
}

export interface ReportLoadProgress {
  stage: keyof typeof STAGE_LABELS
  bytesRead?: number
  totalBytes?: number | null
}

// Awaiting the reporter lets the loader paint before expensive synchronous work.
export type ReportLoadReporter = (progress: ReportLoadProgress) => Promise<void>

/** Give the browser a paint opportunity, including when the tab is hidden. */
export function yieldForPaint(): Promise<void> {
  return new Promise((resolve) => {
    let frame: number | undefined
    let paintTimer: ReturnType<typeof setTimeout> | undefined
    const fallback = setTimeout(finish, 100)
    function finish() {
      clearTimeout(fallback)
      clearTimeout(paintTimer)
      if (frame !== undefined) cancelAnimationFrame(frame)
      resolve()
    }
    if (typeof requestAnimationFrame === 'function' && document.visibilityState !== 'hidden') {
      frame = requestAnimationFrame(() => { paintTimer = setTimeout(finish, 0) })
    } else {
      paintTimer = setTimeout(finish, 0)
    }
  })
}

function formatProgressBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}

/** Update the static splash without requiring Vue or the report view to mount. */
export function createReportLoadReporter(): ReportLoadReporter {
  let lastStage: ReportLoadProgress['stage'] | undefined
  let lastPaint = 0
  return async ({ stage, bytesRead, totalBytes }) => {
    const complete = totalBytes != null && bytesRead === totalBytes
    const shouldYield = stage !== lastStage || complete || performance.now() - lastPaint >= 100
    lastStage = stage

    const label = document.getElementById('report-startup-stage')
    const detail = document.getElementById('report-startup-detail')
    const progress = document.getElementById('report-startup-progress') as HTMLProgressElement | null
    if (label) label.textContent = STAGE_LABELS[stage]
    // Content-Length is not a decoded size for compressed HTTP responses.
    // Only show a percentage within stages whose byte total is actually known.
    const knownTotal = totalBytes != null && totalBytes > 0 &&
      bytesRead != null && bytesRead <= totalBytes
    if (progress) {
      if (knownTotal) {
        progress.max = totalBytes
        progress.value = bytesRead
      } else {
        progress.removeAttribute('value')
      }
    }
    if (detail) {
      detail.textContent = bytesRead == null
        ? 'Large reports may take a moment.'
        : knownTotal
          ? `${formatProgressBytes(bytesRead)} of ${formatProgressBytes(totalBytes)} · ${Math.floor(bytesRead / totalBytes * 100)}% of this step`
          : `${formatProgressBytes(bytesRead)} read`
    }
    if (shouldYield) {
      await yieldForPaint()
      lastPaint = performance.now()
    }
  }
}

/** Remove the splash only after Vue has committed the report or its error view. */
export function finishReportStartup(): void {
  document.getElementById('report-startup')?.remove()
}

/** Keep a readable recovery state if application initialization itself fails. */
export function failReportStartup(): void {
  const splash = document.getElementById('report-startup')
  if (!splash) return
  splash.setAttribute('role', 'alert')
  const label = document.getElementById('report-startup-stage')
  const detail = document.getElementById('report-startup-detail')
  if (label) label.textContent = 'Unable to open report'
  if (detail) detail.textContent = 'Reload this page to try again.'
  splash.querySelector<HTMLElement>('.nv-splash__spinner')?.setAttribute('hidden', '')
  document.getElementById('report-startup-progress')?.setAttribute('hidden', '')
  document.getElementById('report-startup-retry')?.removeAttribute('hidden')
}
