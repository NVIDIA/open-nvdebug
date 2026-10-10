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

import { mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import OnboardingTour from '@/components/common/OnboardingTour.vue'

describe('OnboardingTour browser storage', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.useFakeTimers()
  })

  afterEach(() => {
    document.body.innerHTML = ''
    vi.restoreAllMocks()
    vi.useRealTimers()
  })

  async function showTour() {
    vi.advanceTimersByTime(1000)
    await nextTick()
  }

  it('treats an unavailable storage read as a first visit', async () => {
    const errors: unknown[] = []
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('Storage disabled', 'SecurityError')
    })
    const wrapper = mount(OnboardingTour, {
      attachTo: document.body,
      global: { config: { errorHandler: error => errors.push(error) } },
    })

    await showTour()

    expect(errors).toEqual([])
    expect(document.body.textContent).toContain('Welcome to NVDebug Reports')
    wrapper.unmount()
  })

  it('dismisses without a runtime error when storage writes are unavailable', async () => {
    const errors: unknown[] = []
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('Storage disabled', 'SecurityError')
    })
    const wrapper = mount(OnboardingTour, {
      attachTo: document.body,
      global: { config: { errorHandler: error => errors.push(error) } },
    })
    await showTour()

    const skip = Array.from(document.body.querySelectorAll('button')).find(
      button => button.textContent === 'Skip Tour',
    )
    if (!(skip instanceof HTMLButtonElement)) {
      throw new Error('Missing Skip Tour button')
    }
    skip.click()
    await nextTick()

    expect(errors).toEqual([])
    expect(document.body.textContent).not.toContain('Welcome to NVDebug Reports')
    wrapper.unmount()
  })
})
