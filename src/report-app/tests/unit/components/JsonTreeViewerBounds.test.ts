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
import { describe, expect, it, vi } from 'vitest'
import JsonTreeViewer from '@/components/viewers/JsonTreeViewer.vue'
import { showToast } from '@/composables/useToast'
import {
  MAX_JSON_TREE_DEPTH,
  MAX_JSON_TREE_NODES,
  walkJsonTreeBounded,
} from '@/utils/jsonTree'

vi.mock('@/composables/useToast', () => ({ showToast: vi.fn() }))
vi.mock('@/components/viewers/MonacoViewer.vue', () => ({
  default: { template: '<div data-testid="monaco-viewer-stub" />' },
}))

function deeplyNestedJson(depth: number): string {
  let value: unknown = { needle: 'found' }
  for (let index = 0; index < depth; index += 1) value = { child: value }
  return JSON.stringify(value)
}

describe('JsonTreeViewer traversal bounds', () => {
  it('enforces both depth and aggregate node limits iteratively', () => {
    const deep = JSON.parse(deeplyNestedJson(MAX_JSON_TREE_DEPTH + 4))
    const depthResult = walkJsonTreeBounded(deep, () => undefined)
    const wide = Object.fromEntries(
      Array.from({ length: MAX_JSON_TREE_NODES + 10 }, (_, index) => [`key-${index}`, index]),
    )
    const nodeResult = walkJsonTreeBounded(wide, () => undefined)

    expect(depthResult.truncatedByDepth).toBe(true)
    expect(depthResult.visitedNodes).toBeLessThanOrEqual(MAX_JSON_TREE_DEPTH + 1)
    expect(nodeResult.truncatedByNodes).toBe(true)
    expect(nodeResult.visitedNodes).toBe(MAX_JSON_TREE_NODES)
  })

  it('discloses bounded expand-all traversal in the UI and a toast', async () => {
    vi.mocked(showToast).mockReset()
    const wrapper = mount(JsonTreeViewer, {
      props: { content: deeplyNestedJson(MAX_JSON_TREE_DEPTH + 4) },
      global: {
        stubs: {
          JsonNode: true,
          MonacoViewer: true,
        },
      },
    })

    await wrapper.get('button[aria-label="Expand all"]').trigger('click')

    expect(wrapper.get('[role="status"]').text()).toContain(`depth ${MAX_JSON_TREE_DEPTH}`)
    expect(wrapper.get('[role="status"]').text()).toContain('download the artifact')
    expect(showToast).toHaveBeenCalledWith(expect.stringContaining('download the artifact'), 'info')
  })

  it('discloses when search cannot inspect nodes below the depth bound', async () => {
    const wrapper = mount(JsonTreeViewer, {
      props: { content: deeplyNestedJson(MAX_JSON_TREE_DEPTH + 4) },
      global: {
        stubs: {
          JsonNode: true,
          MonacoViewer: true,
        },
      },
    })

    await wrapper.get('input[placeholder="Search keys/values..."]').setValue('needle')

    expect(wrapper.get('[role="status"]').text()).toContain(`depth ${MAX_JSON_TREE_DEPTH}`)
    expect(wrapper.text()).toContain('0 matches')
  })
})
