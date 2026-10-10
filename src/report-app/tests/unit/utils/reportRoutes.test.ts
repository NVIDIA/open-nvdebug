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
import {
  collectorDetailRoute,
  collectorGroupRoute,
  dutFirmwareRoute,
  dutPreflightRoute,
  dutProfileRoute,
  dutRoute,
} from '@/utils/reportRoutes'

describe('report route builders', () => {
  it('keeps a hostile DUT identifier inside one named-route parameter', () => {
    const resolved = router.resolve(dutRoute('../dut/with?query#fragment'))

    expect(resolved.name).toBe('dut')
    expect(resolved.params.dutId).toBe('../dut/with?query#fragment')
    expect(resolved.href).toContain('..%2Fdut%2Fwith%3Fquery%23fragment')
  })

  it('keeps an anomaly highlight inside the named-route query', () => {
    const resolved = router.resolve(dutRoute('dut/with?query', 'collector#fragment&next=/'))

    expect(resolved.name).toBe('dut')
    expect(resolved.params.dutId).toBe('dut/with?query')
    expect(resolved.query.highlight).toBe('collector#fragment&next=/')
    expect(resolved.href).toContain('dut%2Fwith%3Fquery')
    expect(resolved.href).toContain('highlight=collector%23fragment%26next=/')
  })

  it('encodes every collector route segment without changing route structure', () => {
    const resolved = router.resolve(collectorDetailRoute(
      'dut/../../escape',
      'group?mode=unsafe',
      'collector#fragment',
    ))

    expect(resolved.name).toBe('collector-detail')
    expect(resolved.params).toMatchObject({
      dutId: 'dut/../../escape',
      group: 'group?mode=unsafe',
      collectorId: 'collector#fragment',
    })
    expect(resolved.href).toContain(
      '/dut/dut%2F..%2F..%2Fescape/group%3Fmode=unsafe/collector%23fragment',
    )
  })

  it.each([
    [dutPreflightRoute, 'preflight'],
    [dutFirmwareRoute, 'firmware'],
    [dutProfileRoute, 'dut-profile'],
  ])('keeps hostile DUT identifiers in the %s named route', (builder, routeName) => {
    const resolved = router.resolve(builder('node/../other?mode=unsafe#fragment'))

    expect(resolved.name).toBe(routeName)
    expect(resolved.params.dutId).toBe('node/../other?mode=unsafe#fragment')
    expect(resolved.href).toContain('node%2F..%2Fother%3Fmode=unsafe%23fragment')
  })

  it('encodes collector-group identifiers without creating a new route segment', () => {
    const resolved = router.resolve(collectorGroupRoute('dut/escape', '../group?query#fragment'))

    expect(resolved.name).toBe('collector-group')
    expect(resolved.params).toMatchObject({
      dutId: 'dut/escape',
      group: '../group?query#fragment',
    })
    expect(resolved.href).toContain('/dut/dut%2Fescape/..%2Fgroup%3Fquery%23fragment')
  })
})
