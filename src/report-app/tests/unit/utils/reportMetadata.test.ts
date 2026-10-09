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
import {
  formatAccessPath,
  formatSecurityModeSource,
  formatSecurityModeValue,
} from '@/utils/reportMetadata'

describe('report metadata formatting', () => {
  it('formats canonical access paths without reconstructing them', () => {
    expect(formatAccessPath('redfish')).toBe('Redfish')
    expect(formatAccessPath('host_ssh')).toBe('Host SSH')
    expect(formatAccessPath('bmc_ssh')).toBe('BMC SSH')
    expect(formatAccessPath('ipmi')).toBe('IPMI')
    expect(formatAccessPath('composite')).toBe('Composite')
    expect(formatAccessPath('unknown')).toBe('Unknown')
  })

  it('shows only explicitly reported security-mode evidence', () => {
    expect(formatSecurityModeValue({
      status: 'reported',
      value: false,
      source: 'dut_config.SECURITY_MODE',
    })).toBe('false')
    expect(formatSecurityModeSource({
      status: 'reported',
      value: 2,
      source: 'dut_config.SecurityMode',
    })).toBe('dut_config.SecurityMode')

    const unknown = { status: 'unknown', value: null, source: null } as const
    expect(formatSecurityModeValue(unknown)).toBe('Not reported')
    expect(formatSecurityModeSource(unknown)).toBe('No explicit source')
  })
})
