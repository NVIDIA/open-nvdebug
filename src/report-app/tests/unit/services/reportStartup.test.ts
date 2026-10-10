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

import { readFileSync } from 'node:fs'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createReportLoadReporter, failReportStartup, finishReportStartup, yieldForPaint } from '@/services/reportStartup'

const html = readFileSync('index.html', 'utf8')

describe('report startup screen', () => {
  beforeEach(() => {
    document.body.innerHTML = new DOMParser().parseFromString(html, 'text/html').body.innerHTML
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    document.body.innerHTML = ''
  })

  it('exists before the payload and survives replacing the Vue mount point', () => {
    const splash = document.getElementById('report-startup')!
    expect(splash.getAttribute('role')).toBe('status')
    expect(html.indexOf('id="report-startup"')).toBeLessThan(html.indexOf('<!-- __NVDEBUG_MANIFEST_PLACEHOLDER__ -->'))
    document.getElementById('app')!.replaceChildren(document.createElement('main'))
    expect(document.body.contains(splash)).toBe(true)
  })

  it('shows measured bytes within a step and resets the bar for processing', async () => {
    const report = createReportLoadReporter()
    const pending = report({ stage: 'decompressing', bytesRead: 1024, totalBytes: 4096 })
    const progress = document.getElementById('report-startup-progress') as HTMLProgressElement
    expect(progress.value / progress.max).toBe(0.25)
    expect(document.getElementById('report-startup-detail')!.textContent).toBe('1.0 KiB of 4.0 KiB · 25% of this step')
    await vi.runAllTimersAsync()
    await pending

    const parsing = report({ stage: 'parsing' })
    expect(progress.hasAttribute('value')).toBe(false)
    expect(document.getElementById('report-startup-stage')!.textContent).toBe('Preparing report data…')
    await vi.runAllTimersAsync()
    await parsing
  })

  it.each([null, 512])('does not invent a percentage for unknown or exceeded totals (%s)', async (totalBytes) => {
    const pending = createReportLoadReporter()({ stage: 'reading', bytesRead: 1024, totalBytes })
    expect(document.getElementById('report-startup-progress')!.hasAttribute('value')).toBe(false)
    expect(document.getElementById('report-startup-detail')!.textContent).toBe('1.0 KiB read')
    await vi.runAllTimersAsync()
    await pending
  })

  it('updates counters without delaying every chunk and paints each new stage', async () => {
    const report = createReportLoadReporter()
    const first = report({ stage: 'reading', bytesRead: 10 })
    await vi.runAllTimersAsync()
    await first
    await report({ stage: 'reading', bytesRead: 20 })
    expect(document.getElementById('report-startup-detail')!.textContent).toBe('20 B read')
    expect(vi.getTimerCount()).toBe(0)
    const parsing = report({ stage: 'parsing' })
    expect(document.getElementById('report-startup-stage')!.textContent).toBe('Preparing report data…')
    await vi.runAllTimersAsync()
    await parsing
  })

  it('finishes yielding even if the browser never delivers an animation frame', async () => {
    vi.stubGlobal('requestAnimationFrame', vi.fn(() => 42))
    vi.stubGlobal('cancelAnimationFrame', vi.fn())
    const completed = vi.fn()
    const pending = yieldForPaint().then(completed)
    expect(completed).not.toHaveBeenCalled()
    await vi.runAllTimersAsync()
    await pending
    expect(completed).toHaveBeenCalledOnce()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('replaces the spinner with recovery instructions on failure', () => {
    failReportStartup()
    expect(document.getElementById('report-startup')!.getAttribute('role')).toBe('alert')
    expect(document.getElementById('report-startup-stage')!.textContent).toBe('Unable to open report')
    expect(document.getElementById('report-startup-progress')!.hidden).toBe(true)
    expect(document.getElementById('report-startup-retry')!.hidden).toBe(false)
  })

  it('removes the splash when the report is ready', () => {
    finishReportStartup()
    expect(document.getElementById('report-startup')).toBeNull()
    expect(document.getElementById('app')).not.toBeNull()
  })
})
