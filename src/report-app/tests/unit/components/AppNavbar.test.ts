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

import { createPinia, setActivePinia } from 'pinia'
import { shallowMount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AppNavbar from '@/components/layout/AppNavbar.vue'
import { useManifestStore } from '@/stores/manifest'
import type { Manifest, RunIdentity } from '@/types/manifest'

const route = { path: '/' }

vi.mock('vue-router', () => ({
  useRoute: () => route,
}))

const RUN_IDENTITY: RunIdentity = {
  schema_version: '1.1',
  tool: {
    version: '2.2.0',
    build_hash: '86aeb7a',
    source_mode: 'source',
    source_revision: '1'.repeat(40),
    build_timestamp_utc: '2026-08-07T12:34:56Z',
  },
  catalog: {
    name: 'Telemetry_Catalog_v2.2.xlsx',
    version: '2.2',
    sha256: '2'.repeat(64),
    size_bytes: 1024,
    binding: 'manifest_bound',
  },
  effective_config_sha256: '3'.repeat(64),
  invocation: {
    resolved_level: 'L2',
    resolved_profile: 'level',
    resolved_plan_sha256: '6'.repeat(64),
    invocation_sha256: '4'.repeat(64),
  },
  output: {
    mode: 'configured_generated',
    caller_relation: 'absent',
    caller_path: {
      path_sha256: null,
      version_alignment: 'not_declared',
      level_alignment: 'not_declared',
      profile_alignment: 'not_declared',
    },
    resolved_path: {
      path_sha256: '7'.repeat(64),
      version_alignment: 'aligned',
      level_alignment: 'aligned',
      profile_alignment: 'aligned',
    },
    generated_path: {
      path_sha256: '7'.repeat(64),
      version_alignment: 'aligned',
      level_alignment: 'aligned',
      profile_alignment: 'aligned',
    },
  },
  identity_sha256: '5'.repeat(64),
}

function mountNavbar() {
  return shallowMount(AppNavbar, {
    global: {
      mocks: { $route: route },
      stubs: { RouterLink: true, Transition: false },
    },
  })
}

describe('AppNavbar run identity', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1440 })
  })

  it('renders report identity metadata only from the validated store identity', () => {
    const store = useManifestStore()
    store.manifest = {
      tool_version: '9.9.9',
      tool_config: {
        collection_level: 'L3',
        collection_profile: 'custom',
      },
      run_identity: RUN_IDENTITY,
    } as Manifest

    const wrapper = mountNavbar()
    const identity = wrapper.get('[data-testid="run-identity"]')

    expect(identity.text()).toContain('v2.2.0')
    expect(identity.text()).toContain('L2 / level')
    expect(identity.text()).toContain('5'.repeat(12))
    expect(identity.text()).not.toContain('9.9.9')
    expect(identity.text()).not.toContain('L3')
    expect(identity.attributes('title')).toContain(RUN_IDENTITY.identity_sha256)
    wrapper.unmount()
  })

  it('does not manufacture identity metadata for a legacy report', () => {
    const store = useManifestStore()
    store.manifest = {
      tool_version: '2.1.0',
      tool_config: { collection_level: 'L2' },
    } as Manifest

    const wrapper = mountNavbar()
    expect(wrapper.find('[data-testid="run-identity"]').exists()).toBe(false)
    wrapper.unmount()
  })
})
