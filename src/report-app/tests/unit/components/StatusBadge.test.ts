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
import StatusBadge from '@/components/common/StatusBadge.vue'

describe('StatusBadge', () => {
  it.each([
    ['interrupted', 'Interrupted'],
    [' Interrupted ', 'Interrupted'],
    ['cancelled', 'Cancelled'],
    ['CANCELED', 'Cancelled'],
  ])('renders terminal status %j as a warning', (status, label) => {
    const wrapper = mount(StatusBadge, { props: { status } })

    expect(wrapper.text()).toBe(label)
    expect(wrapper.classes()).toContain('nv-badge--warning')
  })

  it('normalizes an empty status to unknown', () => {
    const wrapper = mount(StatusBadge, { props: { status: '  ' } })

    expect(wrapper.text()).toBe('Unknown')
    expect(wrapper.classes()).toContain('nv-badge--unknown')
  })

  it('keeps existing status aliases intact', () => {
    const wrapper = mount(StatusBadge, { props: { status: 'Passed' } })

    expect(wrapper.text()).toBe('Success')
    expect(wrapper.classes()).toContain('nv-badge--success')
  })
})
