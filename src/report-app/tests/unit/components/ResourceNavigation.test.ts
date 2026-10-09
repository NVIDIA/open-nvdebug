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

import { createPinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'
import appRouter from '@/router'
import AnalysisNav from '@/components/common/AnalysisNav.vue'
import QuickActions from '@/components/dashboard/QuickActions.vue'
import AppNavbar from '@/components/layout/AppNavbar.vue'

function testRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div />' } },
      { path: '/resources', component: { template: '<div />' } },
    ],
  })
}

afterEach(() => {
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1280 })
})

describe('resource navigation', () => {
  it('registers the first-class resource route and sidebar link', async () => {
    expect(appRouter.getRoutes().find(route => route.name === 'resources')?.path).toBe('/resources')

    const router = testRouter()
    await router.push('/')
    await router.isReady()
    const wrapper = mount(AnalysisNav, { global: { plugins: [router] } })
    const link = wrapper.findAll('a').find(anchor => anchor.text() === 'Resource Usage')

    expect(link?.attributes('href')).toContain('/resources')
  })

  it('exposes Resource Usage in the desktop Analysis menu', async () => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1280 })
    const router = testRouter()
    await router.push('/resources')
    await router.isReady()
    const wrapper = mount(AppNavbar, { global: { plugins: [createPinia(), router] } })

    const analysisButton = wrapper.findAll('button').find(button => button.text().includes('Analysis'))!
    await analysisButton.trigger('click')

    expect(wrapper.text()).toContain('Resource Usage')
    expect(analysisButton.classes()).toContain('navbar-link--active')
  })

  it('exposes Resource Usage in the mobile menu', async () => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 800 })
    const router = testRouter()
    await router.push('/')
    await router.isReady()
    const wrapper = mount(AppNavbar, { global: { plugins: [createPinia(), router] } })

    await wrapper.get('button[aria-label="Toggle sidebar"]').trigger('click')

    expect(wrapper.findAll('.nv-navbar__mobile-link').some(link => link.text() === 'Resource Usage')).toBe(true)
  })

  it('links to Resource Usage from dashboard quick actions', async () => {
    const router = testRouter()
    await router.push('/')
    await router.isReady()
    const wrapper = mount(QuickActions, { global: { plugins: [createPinia(), router] } })
    const link = wrapper.findAll('a').find(anchor => anchor.text().includes('Resource Usage'))

    expect(link?.attributes('href')).toContain('/resources')
  })
})
