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

import { afterEach, describe, expect, it, vi } from 'vitest'
import { copyToClipboard } from '@/utils/clipboard'

describe('clipboard output boundary', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true })
  })

  it('neutralizes every spreadsheet cell before using the Clipboard API', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })

    await copyToClipboard('=first\nordinary\t  @third')

    expect(writeText).toHaveBeenCalledOnce()
    expect(writeText).toHaveBeenCalledWith("'=first\nordinary\t'  @third")
  })

  it('applies the same neutralization to the textarea fallback', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('not allowed'))
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })
    let copiedValue = ''
    Object.defineProperty(document, 'execCommand', {
      configurable: true,
      value: vi.fn(() => {
        copiedValue = document.querySelector('textarea')?.value ?? ''
        return true
      }),
    })

    await copyToClipboard('+fallback')

    expect(copiedValue).toBe("'+fallback")
    expect(document.querySelector('textarea')).toBeNull()
  })
})
