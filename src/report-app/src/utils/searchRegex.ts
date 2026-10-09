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

export const MAX_SEARCH_REGEX_LENGTH = 256

/** Compile the analyst-selected regular-expression search mode. */
export function compileSearchRegex(query: string): RegExp {
  if (query.length > MAX_SEARCH_REGEX_LENGTH) {
    throw new RangeError(
      `Regular-expression searches are limited to ${MAX_SEARCH_REGEX_LENGTH} characters`,
    )
  }

  // The pattern is local analyst input, never collected bundle content, and
  // its size is bounded above. Regex search is an explicit UI mode whose
  // syntax must remain available for diagnostic workflows.
  // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
  return new RegExp(query, 'gi')
}
