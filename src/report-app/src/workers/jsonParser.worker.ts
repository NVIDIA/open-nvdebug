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

/**
 * JSON parser worker — parses large JSON strings without blocking UI.
 *
 * Input: { content: string }
 * Output: { data: any, error?: string }
 */

export function handleMessage(data: { content: string }): {
  data: any
  error?: string
} {
  try {
    const parsed = JSON.parse(data.content)
    return { data: parsed }
  } catch (e) {
    return { data: null, error: e instanceof Error ? e.message : String(e) }
  }
}

if (typeof self !== 'undefined' && typeof (self as any).onmessage !== 'undefined') {
  self.onmessage = (event: MessageEvent) => {
    const result = handleMessage(event.data)
    self.postMessage(result)
  }
}
