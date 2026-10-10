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

import { describe, expect, it } from 'vitest'
import router from '@/router'

describe('report router', () => {
  it('publishes one unique name for every supported report route', () => {
    const routes = router.getRoutes()
    const names = routes.map(route => String(route.name))

    expect(routes).toHaveLength(32)
    expect(new Set(names).size).toBe(routes.length)
    expect(names).toEqual(expect.arrayContaining([
      'dashboard',
      'collector-detail',
      'file',
      'correlate',
      'compare-runs',
      'split-file',
    ]))
  })

  it('resolves dynamic identities and the complete encoded file tail', () => {
    expect(router.resolve('/dut/DUT_1/redfish/R17').matched.at(-1)?.name)
      .toBe('collector-detail')

    const file = router.resolve('/file/DUT_1%2Fhost%2Fsystem.log')
    expect(file.name).toBe('file')
    expect(file.params.encodedPath).toBe('DUT_1/host/system.log')
  })
})
