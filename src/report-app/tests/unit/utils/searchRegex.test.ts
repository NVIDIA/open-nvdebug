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
import { compileSearchRegex, MAX_SEARCH_REGEX_LENGTH } from '@/utils/searchRegex'

describe('compileSearchRegex', () => {
  it('preserves explicit regular-expression search syntax', () => {
    const pattern = compileSearchRegex('error\\s+code=(?<code>\\d+)')

    expect(pattern.exec('ERROR code=42')?.groups?.code).toBe('42')
  })

  it('rejects oversized patterns before constructing RegExp', () => {
    expect(() => compileSearchRegex('a'.repeat(MAX_SEARCH_REGEX_LENGTH + 1))).toThrow(
      `Regular-expression searches are limited to ${MAX_SEARCH_REGEX_LENGTH} characters`,
    )
  })

  it('reports invalid analyst regex syntax', () => {
    expect(() => compileSearchRegex('[')).toThrow(SyntaxError)
  })
})
