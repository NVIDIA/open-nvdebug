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
  neutralizeCsvFormula,
  neutralizeSpreadsheetClipboardText,
  serializeCsv,
  serializeCsvCell,
  serializeTsvCell,
} from '@/utils/csv'

describe('spreadsheet-safe CSV serialization', () => {
  it.each([
    '=HYPERLINK("https://attacker.invalid", "open")',
    '+cmd|calc',
    '-1+2',
    '@SUM(1,2)',
    '  =1+1',
    '\t@SUM(1,2)',
    '\r\n-HYPERLINK("https://attacker.invalid")',
    '\u0000+1+1',
    '\u0085=1+1',
    '\u00a0@SUM(1,2)',
    '\u200b-HYPERLINK("https://attacker.invalid")',
    '\u202a=1+1',
    '\ufeff+1+1',
  ])('neutralizes formula trigger behind ignorable prefixes: %j', value => {
    expect(neutralizeCsvFormula(value)).toBe(`'${value}`)
  })

  it.each([
    '',
    'ordinary text',
    '1+1',
    'user@example.com',
    'value - 1',
    "'=1+1",
    '"=1+1',
    '．=1+1',
    '＝1+1',
  ])('does not alter non-formula text: %j', value => {
    expect(neutralizeCsvFormula(value)).toBe(value)
  })

  it('quotes delimiters, quotes, and either newline spelling', () => {
    expect(serializeCsvCell('alpha,beta')).toBe('"alpha,beta"')
    expect(serializeCsvCell('say "hello"')).toBe('"say ""hello"""')
    expect(serializeCsvCell('line one\nline two')).toBe('"line one\nline two"')
    expect(serializeCsvCell('line one\rline two')).toBe('"line one\rline two"')
  })

  it('neutralizes before quoting without losing the original data', () => {
    expect(serializeCsvCell(' =SUM(1,2)')).toBe('"\' =SUM(1,2)"')
    expect(serializeCsvCell('\r\n@SUM(1,2)')).toBe('"\'\r\n@SUM(1,2)"')
  })

  it('serializes complete rectangular data with CRLF record boundaries', () => {
    expect(serializeCsv([
      ['plain', 'with,comma', 'say "hello"'],
      ['=1+1', 'line\nbreak', null],
      [undefined, 42, false],
    ])).toBe(
      'plain,"with,comma","say ""hello"""\r\n' +
      '\'=1+1,"line\nbreak",\r\n' +
      ',42,false',
    )
  })

  it('keeps clipboard cells rectangular and neutralizes formulas', () => {
    expect(serializeTsvCell('=1+1')).toBe("'=1+1")
    expect(serializeTsvCell('safe\t=2+2\n@SUM(1,2)')).toBe(
      'safe\\t=2+2\\n@SUM(1,2)',
    )
    expect(serializeTsvCell('path\\to\\file')).toBe('path\\\\to\\\\file')
  })

  it('neutralizes every raw clipboard line without changing line endings', () => {
    expect(neutralizeSpreadsheetClipboardText(
      '=first\r\nordinary\r  @third\n\t-fourth\n',
    )).toBe(
      "'=first\r\nordinary\r'  @third\n\t'-fourth\n",
    )
  })

  it('neutralizes formulas in every tab-delimited clipboard cell', () => {
    expect(neutralizeSpreadsheetClipboardText(
      'ordinary\t+second\t  =third',
    )).toBe(
      "ordinary\t'+second\t'  =third",
    )
  })

  it('preserves ordinary raw clipboard text and nullish values', () => {
    expect(neutralizeSpreadsheetClipboardText('first\nsecond')).toBe('first\nsecond')
    expect(neutralizeSpreadsheetClipboardText(null)).toBe('')
    expect(neutralizeSpreadsheetClipboardText(undefined)).toBe('')
  })
})
