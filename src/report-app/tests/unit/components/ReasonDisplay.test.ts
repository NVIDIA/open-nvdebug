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
import ReasonDisplay from '@/components/common/ReasonDisplay.vue'
import { copyToClipboard } from '@/utils/clipboard'

vi.mock('@/utils/clipboard', () => ({
  copyToClipboard: vi.fn(),
}))

describe('ReasonDisplay', () => {
  beforeEach(() => {
    vi.mocked(copyToClipboard).mockReset().mockResolvedValue(undefined)
  })

  it('renders canonical diagnostic sections and bullets on visual lines', () => {
    const raw = 'Stage failed. Details: Device Errors: • sma 0: - All entities failed. Details: Other Errors: • no dump location'
    const wrapper = mount(ReasonDisplay, { props: { text: raw } })
    const displayed = wrapper.get('.rd__text--diagnostic').text()

    expect(displayed).toContain('Device Errors:\n• sma 0:\n  - All entities failed.')
    expect(displayed).toContain('Other Errors:\n• no dump location')
  })

  it('keeps unrelated bullet text in the plain-text path', () => {
    const wrapper = mount(ReasonDisplay, { props: { text: 'Captured values: • one • two' } })
    expect(wrapper.find('.rd__text--diagnostic').exists()).toBe(false)
    expect(wrapper.get('.rd__text').text()).toBe('Captured values: • one • two')
  })

  it('prioritizes diagnostic hierarchy when a bullet contains embedded JSON', () => {
    const raw = 'Failed operations: HTTP Errors: • System_0: - 404: {"error":"missing"}'
    const wrapper = mount(ReasonDisplay, { props: { text: raw } })

    expect(wrapper.get('.rd__text--diagnostic').text()).toContain(
      'HTTP Errors:\n• System_0:\n  - 404: {"error":"missing"}',
    )
  })

  it('delegates raw reasons to the centrally hardened clipboard boundary', async () => {
    const wrapper = mount(ReasonDisplay, {
      props: { text: '=first\nordinary\n\t@third' },
    })

    await wrapper.get('.rd__copy').trigger('click')
    await flushPromises()

    expect(copyToClipboard).toHaveBeenCalledWith(
      '=first\nordinary\n\t@third',
    )
  })
})

const PAYLOADS = [
  '<img id="reason-image-probe" src=x onerror=alert(1)>',
  '</pre><script id="reason-script-probe">alert(1)</script><pre>',
  '" onload="alert(1)" data-probe="reason-attribute-probe',
]

describe('ReasonDisplay JSON highlighting', () => {
  it.each(PAYLOADS)('renders hostile JSON as text: %s', (payload) => {
    const wrapper = mount(ReasonDisplay, {
      props: { text: JSON.stringify({ reason: payload }) },
    })

    expect(wrapper.find('img').exists()).toBe(false)
    expect(wrapper.find('script').exists()).toBe(false)
    expect(JSON.parse(wrapper.get('pre').text()).reason).toBe(payload)
    const highlightedElements = [...wrapper.get('pre').element.querySelectorAll('*')]
    expect(highlightedElements.every(element => element.tagName === 'SPAN')).toBe(true)
    expect(highlightedElements.every(element => [
      'rd-hl-text', 'rd-hl-key', 'rd-hl-str', 'rd-hl-num', 'rd-hl-kw',
    ].includes(element.className))).toBe(true)
  })

  it('keeps embedded JSON payloads inside the inline preformatted block', () => {
    const payload = '</pre><script id="mixed-reason-probe">alert(1)</script>'
    const wrapper = mount(ReasonDisplay, {
      props: { text: `collector failed: ${JSON.stringify({ reason: payload })}` },
    })

    expect(wrapper.find('#mixed-reason-probe').exists()).toBe(false)
    expect(JSON.parse(wrapper.get('pre').text()).reason).toBe(payload)
  })
})
