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
import { nextTick } from 'vue'
import { describe, expect, it } from 'vitest'
import FileTree from '@/components/common/FileTree.vue'
import type { FileEntry } from '@/types/manifest'
import { buildFileTree, reportPathSegments } from '@/utils/fileTree'

function file(path: string, size = 1): FileEntry {
  return {
    path,
    size,
    type: 'text',
    collector_id: 'T1',
    dut_id: 'dut',
    collector_group: 'group',
    collector_name: 'collector',
  }
}

function allNodes(nodes: ReturnType<typeof buildFileTree>): ReturnType<typeof buildFileTree> {
  return nodes.flatMap(node => [node, ...allNodes(node.children ?? [])])
}

describe('FileTree', () => {
  it('keeps prototype-sensitive path segments as inert Map keys', () => {
    const before = Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')
    const tree = buildFileTree([
      file('__proto__/polluted/report.log'),
      file('constructor/prototype/second.log'),
    ])

    expect(tree.map(node => node.name)).toEqual(['__proto__', 'constructor'])
    expect(tree[0].children?.[0].name).toBe('polluted')
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')).toBe(before)
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, '__files__')).toBe(false)
    expect(({} as Record<string, unknown>).polluted).toBeUndefined()
  })

  it.each([
    '',
    '/absolute.log',
    'double//segment.log',
    './relative.log',
    'folder/../escape.log',
    String.raw`windows\ambiguous.log`,
    'control/line\nbreak.log',
  ])('rejects malformed bundle path %j', path => {
    expect(reportPathSegments(path)).toBeNull()
    expect(buildFileTree([file(path)])).toEqual([])
  })

  it.each([undefined, null, 7, true, {}, []])(
    'rejects non-string path value %j without throwing',
    path => {
      expect(reportPathSegments(path)).toBeNull()
      expect(buildFileTree([{ path }])).toEqual([])
    },
  )

  it('skips malformed file-index entries without aborting valid rendering', () => {
    const entries: unknown[] = [
      null,
      undefined,
      7,
      true,
      [],
      {},
      { path: 42 },
      file('dut/valid.log'),
    ]

    const nodes = allNodes(buildFileTree(entries))
    expect(nodes.filter(node => node.filePath).map(node => node.filePath)).toEqual([
      'dut/valid.log',
    ])
  })

  it('deduplicates paths with input-order-neutral display metadata', () => {
    const larger = file('dut/duplicate.log', 20)
    const smaller = file('dut/duplicate.log', 10)

    const forward = buildFileTree([larger, smaller])
    const reverse = buildFileTree([smaller, larger])

    expect(reverse).toEqual(forward)
    const files = allNodes(forward).filter(node => node.filePath)
    expect(files).toHaveLength(1)
    expect(files[0]).toMatchObject({ filePath: 'dut/duplicate.log', fileSize: 10 })
  })

  it.each([
    [file('a'), file('a/b.log')],
    [file('a/b.log'), file('a')],
  ])('rejects a file/directory prefix collision in either input order', (first, second) => {
    const nodes = allNodes(buildFileTree([first, second]))
    const files = nodes.filter(node => node.filePath)

    expect(files.map(node => node.filePath)).toEqual(['a/b.log'])
    expect(new Set(nodes.map(node => node.path)).size).toBe(nodes.length)
  })

  it('enforces path, segment, and depth boundaries', () => {
    const maxDepth = Array.from({ length: 256 }, (_, index) => `s${index}`).join('/')
    const overDepth = `${maxDepth}/overflow`
    const maxSegment = 'x'.repeat(255)
    const overSegment = 'x'.repeat(256)
    const maxPath = [
      ...Array.from({ length: 15 }, () => 'x'.repeat(255)),
      'x'.repeat(254),
      'x',
    ].join('/')

    expect(maxPath).toHaveLength(4096)
    expect(reportPathSegments(maxDepth)).toHaveLength(256)
    expect(reportPathSegments(overDepth)).toBeNull()
    expect(reportPathSegments(maxSegment)).toEqual([maxSegment])
    expect(reportPathSegments(overSegment)).toBeNull()
    expect(reportPathSegments(maxPath)).toHaveLength(17)
    expect(reportPathSegments(`${maxPath}x`)).toBeNull()

    const deepNodes = allNodes(buildFileTree([file(maxDepth)]))
    expect(deepNodes).toHaveLength(256)
    expect(deepNodes[deepNodes.length - 1].filePath).toBe(maxDepth)
  })

  it('renders, expands, counts, and selects valid nested files', async () => {
    const wrapper = mount(FileTree, {
      props: {
        files: [file('dut/logs/second.log', 2), file('dut/logs/first.log', 1)],
      },
    })
    await nextTick()

    expect(wrapper.text()).toContain('dut')
    expect(wrapper.text()).toContain('2')

    const logsFolder = wrapper.findAll('.nv-sidebar__link').find(row => row.text().includes('logs'))
    expect(logsFolder).toBeDefined()
    expect(wrapper.text()).toContain('first.log')

    await logsFolder!.trigger('click')
    await nextTick()
    expect(wrapper.text()).not.toContain('first.log')

    await logsFolder!.trigger('click')
    await nextTick()
    expect(wrapper.text()).toContain('first.log')

    const firstFile = wrapper.findAll('.nv-sidebar__link').find(row => row.text().includes('first.log'))
    expect(firstFile).toBeDefined()
    await firstFile!.trigger('click')
    expect(wrapper.emitted('file-click')).toEqual([['dut/logs/first.log']])
  })
})
