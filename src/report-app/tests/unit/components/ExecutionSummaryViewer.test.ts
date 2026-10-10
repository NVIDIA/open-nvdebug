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
import { describe, expect, it } from 'vitest'
import ExecutionSummaryViewer from '@/components/viewers/ExecutionSummaryViewer.vue'

const HEADER = 'Collection Name\tID\tExecution Status\tLog Path\tDuration (s)\tReason\tArtifact Paths\tDiagnostic Paths\tFailure Category'

describe('ExecutionSummaryViewer', () => {
  it('renders collector rows with expandable categorized paths', () => {
    const content = `${HEADER}\nsma_debug_dump\tR39\tError\terror.log\t35.1\tDevice Errors: • System_0: - no dump\tartifact.json\tdiagnostic.json\tinternal-error`
    const wrapper = mount(ExecutionSummaryViewer, { props: { content } })

    expect(wrapper.get('.esv__collector').text()).toContain('sma_debug_dump')
    expect(wrapper.get('.esv__paths summary').text()).toBe('2 paths')
    expect(wrapper.findAll('.esv__path-group li').map(item => item.text())).toEqual([
      'artifact.json',
      'diagnostic.json',
    ])
  })

  it('falls back to original raw text for malformed content', () => {
    const content = `${HEADER}\nmalformed row`
    const wrapper = mount(ExecutionSummaryViewer, { props: { content } })

    expect(wrapper.get('.esv__raw').text()).toBe(content)
    expect(wrapper.get('.esv__warning').text()).toContain('original text')
    expect(wrapper.find('.esv__table').exists()).toBe(false)
  })
})
