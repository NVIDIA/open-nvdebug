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

import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import LogViewer from '@/components/viewers/LogViewer.vue'
import { copyToClipboard } from '@/utils/clipboard'
import {
  MAX_LOG_LINE_CHARACTERS,
  MAX_LOG_PREVIEW_CHARACTERS,
  MAX_LOG_PREVIEW_LINES,
  parseLogLine,
  parseLogPreview,
} from '@/utils/logLines'

vi.mock('@/utils/clipboard', () => ({
  copyToClipboard: vi.fn(),
}))

describe('bounded log parsing', () => {
  beforeEach(() => {
    vi.mocked(copyToClipboard).mockReset().mockResolvedValue(undefined)
  })

  it('parses the supported structured format without a regular expression', () => {
    expect(parseLogLine('[2026-08-06] [ERROR] [redfish] failed')).toMatchObject({
      timestamp: '2026-08-06',
      level: 'ERROR',
      component: 'redfish',
      message: 'failed',
      truncated: false,
    })
  })

  it('treats malformed bracket corpora as plain text with bounded retained size', () => {
    const parsed = parseLogLine('['.repeat(MAX_LOG_LINE_CHARACTERS * 8))

    expect(parsed.timestamp).toBeNull()
    expect(parsed.message).toBe(parsed.raw)
    expect(parsed.truncated).toBe(true)
    expect(parsed.raw.length).toBeLessThanOrEqual(MAX_LOG_LINE_CHARACTERS + 32)
  })

  it('recognizes collector tags without replacing the component and preserves tags when copying', async () => {
    const content = '[time] [ERROR] [CID:R1] [redfish] failed'
    expect(parseLogLine(content)).toMatchObject({
      collectorId: 'R1', component: 'redfish', message: 'failed', level: 'ERROR',
    })
    expect(parseLogLine('[time] [INFO] [runner] mentions [CID:R1]').collectorId).toBeNull()
    const wrapper = mount(LogViewer, { props: { content } })
    await wrapper.get('select[aria-label="Log component"]').setValue('redfish')
    expect(wrapper.get('.nv-log__content').text()).toContain('[CID:R1]')
    await wrapper.get('button[title="Copy filtered"]').trigger('click')
    await flushPromises()
    expect(copyToClipboard).toHaveBeenCalledWith(content)
  })

  it('parses the configured runtime format used by live collections', async () => {
    const content = '2026-09-17 10:00:00.001 - CID:R10] [BaseService - INFO - request started - GET'
    expect(parseLogLine(content)).toMatchObject({
      timestamp: '2026-09-17 10:00:00.001', level: 'INFO', collectorId: 'R10',
      component: 'BaseService', message: 'request started - GET',
    })
    expect(parseLogLine('2026-09-17 10:00:00,001 - runner - INFO - mentions CID:R10] [BaseService'))
      .toMatchObject({ collectorId: null, component: 'runner' })
    const wrapper = mount(LogViewer, { props: { content } })
    await wrapper.get('select[aria-label="Log component"]').setValue('BaseService')
    expect(wrapper.get('.nv-log__content').text()).toContain('request started - GET')
    await wrapper.get('button[title="Copy filtered"]').trigger('click')
    await flushPromises()
    expect(copyToClipboard).toHaveBeenCalledWith(content)
  })

  it('enforces deterministic scan, line, and retained-memory budgets', () => {
    const corpus = Array.from({ length: MAX_LOG_PREVIEW_LINES * 2 }, () => '[[[[').join('\n')
    const result = parseLogPreview(corpus)

    expect(result.lines.length).toBeLessThanOrEqual(MAX_LOG_PREVIEW_LINES)
    expect(result.inspectedCharacters).toBeLessThanOrEqual(MAX_LOG_PREVIEW_CHARACTERS)
    expect(result.storedCharacters).toBeLessThanOrEqual(
      MAX_LOG_PREVIEW_CHARACTERS + MAX_LOG_PREVIEW_LINES * 32,
    )
    expect(result.omittedCharacters).toBeGreaterThan(0)
    expect(result.lineLimitReached).toBe(true)
    expect(result.truncated).toBe(true)
  })

  it('never inspects content beyond the documented character budget', () => {
    const result = parseLogPreview('x'.repeat(MAX_LOG_PREVIEW_CHARACTERS + 257))

    expect(result.inspectedCharacters).toBe(MAX_LOG_PREVIEW_CHARACTERS)
    expect(result.omittedCharacters).toBe(257)
    expect(result.storedCharacters).toBeLessThanOrEqual(MAX_LOG_LINE_CHARACTERS + 32)
  })

  it('shows the bounded-preview policy while preserving valid level filtering', async () => {
    const wrapper = mount(LogViewer, {
      props: {
        content: `[time] [INFO] [one] visible\n${'x'.repeat(MAX_LOG_LINE_CHARACTERS + 1)}`,
      },
    })

    expect(wrapper.get('[role="status"]').text()).toContain('long lines truncated')
    expect(wrapper.text()).toContain('visible')

    await wrapper.get('select').setValue('INFO')
    expect(wrapper.text()).toContain('visible')
    expect(wrapper.text()).not.toContain('[line truncated]')
  })

  it('delegates raw lines to the centrally hardened clipboard boundary', async () => {
    const wrapper = mount(LogViewer, {
      props: {
        content: '=first\nordinary\t+second-cell\n  @third',
      },
    })

    await wrapper.get('button[title="Copy filtered"]').trigger('click')
    await flushPromises()

    expect(copyToClipboard).toHaveBeenCalledWith(
      '=first\nordinary\t+second-cell\n  @third',
    )
  })
})
