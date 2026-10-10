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
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import DataTable from '@/components/common/DataTable.vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { copyToClipboard } from '@/utils/clipboard'

vi.mock('@/utils/clipboard', () => ({
  copyToClipboard: vi.fn(),
}))

describe('DataTable search highlighting', () => {
  beforeAll(() => {
    vi.stubGlobal('ResizeObserver', class {
      observe = vi.fn()
      disconnect = vi.fn()
    })
  })

  afterAll(() => {
    vi.unstubAllGlobals()
  })

  beforeEach(() => {
    vi.mocked(copyToClipboard).mockReset()
  })

  it('renders untrusted cell content as text while highlighting matches', async () => {
    const payload = '<img src=x onerror=alert(1)> match[1]'
    const wrapper = mount(DataTable, {
      props: {
        columns: [{ key: 'value', label: 'Value' }],
        data: [{ value: payload }],
        searchable: true,
      },
    })

    await wrapper.get('.dt-search__input').setValue('match[1]')

    const cell = wrapper.get('td')
    expect(cell.find('img').exists()).toBe(false)
    expect(cell.element.textContent).toBe(payload)
    expect(cell.get('mark.dt-highlight').text()).toBe('match[1]')
  })

  it('formats each rendered fallback cell once per render', () => {
    const formatter = vi.fn((value: unknown) => String(value))

    const wrapper = mount(DataTable, {
      props: {
        columns: [{ key: 'value', label: 'Value', formatter }],
        data: [{ value: 'formatted once' }],
      },
    })

    expect(wrapper.get('td').text()).toBe('formatted once')
    // The header's distinct-value cache formats the value once. Rendering the
    // fallback cell must add only one call, not separate highlight/display calls.
    expect(formatter).toHaveBeenCalledTimes(2)
  })

  it('copies a spreadsheet-safe rectangular table', async () => {
    const wrapper = mount(DataTable, {
      props: {
        columns: [
          { key: 'value', label: '=Untrusted header' },
          { key: 'details', label: 'Details' },
        ],
        data: [{
          value: '=HYPERLINK("https://attacker.invalid", "open")',
          details: 'safe\t=2+2\n@SUM(1,2)',
        }],
      },
    })

    await wrapper.get('button[title="Copy table to clipboard"]').trigger('click')
    await flushPromises()

    expect(copyToClipboard).toHaveBeenCalledWith(
      "'=Untrusted header\tDetails\n" +
      "'=HYPERLINK(\"https://attacker.invalid\", \"open\")\t" +
      'safe\\t=2+2\\n@SUM(1,2)',
    )
  })

  it('restores sort, filter, and pagination when returning from a detail route', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/:view', component: { template: '<div />' } }],
    })
    await router.push('/collectors')
    const props = {
      columns: [{ key: 'id', label: 'ID' }],
      data: Array.from({ length: 30 }, (_, id) => ({ id: `collector-${id + 1}` })),
      searchable: true,
      pageSize: 10,
    }
    let wrapper = mount(DataTable, { props, global: { plugins: [router] } })
    await wrapper.get('.dt-search__input').setValue('collector')
    await wrapper.get('th').trigger('click')
    await wrapper.get('th').trigger('click')
    await wrapper.findAll('button').find(button => button.text() === 'Next')!.trigger('click')
    expect(wrapper.findAll('tbody tr')[0].text()).toBe('collector-20')

    // The route changes before Vue disposes the exiting view.
    await router.push('/details')
    wrapper.unmount()
    const detail = mount(DataTable, { props, global: { plugins: [router] } })
    expect(detail.get('th').attributes('aria-sort')).toBeUndefined()
    detail.unmount()
    await router.push('/collectors')
    wrapper = mount(DataTable, { props, global: { plugins: [router] } })

    expect(wrapper.get('th').attributes('aria-sort')).toBe('descending')
    expect((wrapper.get('.dt-search__input').element as HTMLInputElement).value).toBe('collector')
    expect(wrapper.get('.dt-footer__page').text()).toBe('2 / 3')
    expect(wrapper.findAll('tbody tr')[0].text()).toBe('collector-20')
    wrapper.unmount()
  })

  it('offers a visible details action only for navigable rows', async () => {
    const onRowClick = vi.fn()
    const props = { columns: [{ key: 'id', label: 'ID' }], data: [{ id: 'R1' }] }
    const wrapper = mount(DataTable, { props: { ...props, onRowClick } })
    const action = wrapper.get('button[aria-label="View details for R1"]')
    await action.trigger('click')
    expect(onRowClick).toHaveBeenCalledExactlyOnceWith({ id: 'R1' })
    expect(wrapper.get('tbody tr').attributes('data-clickable')).toBe('')
    wrapper.unmount()

    const staticTable = mount(DataTable, { props })
    expect(staticTable.find('.dt-row-action').exists()).toBe(false)
    expect(staticTable.get('tbody tr').attributes('data-clickable')).toBeUndefined()
    staticTable.unmount()
  })

  it('sorts via keyboard and does not open a second row from a nested button', async () => {
    const onRowClick = vi.fn()
    const wrapper = mount(DataTable, {
      props: { columns: [{ key: 'id', label: 'ID' }], data: [{ id: 'R2' }, { id: 'R1' }], onRowClick },
    })
    await wrapper.get('th').trigger('keydown', { key: 'Enter' })
    expect(wrapper.get('th').attributes('aria-sort')).toBe('ascending')
    const filterSpace = new KeyboardEvent('keydown', { key: ' ', bubbles: true, cancelable: true })
    wrapper.get('.dt-col-filter-btn').element.dispatchEvent(filterSpace)
    expect(filterSpace.defaultPrevented).toBe(false)
    await wrapper.get('.dt-scroll').trigger('keydown', { key: 'ArrowDown' })
    await wrapper.get('button[aria-label="View details for R2"]').trigger('keydown', { key: 'Enter' })
    expect(onRowClick).not.toHaveBeenCalled()
    await wrapper.get('button[aria-label="View details for R2"]').trigger('click')
    expect(onRowClick).toHaveBeenCalledExactlyOnceWith({ id: 'R2' })
    wrapper.unmount()
  })
})
