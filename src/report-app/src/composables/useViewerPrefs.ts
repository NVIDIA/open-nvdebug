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

import { ref, watch } from 'vue'

const STORAGE_KEY = 'nv-viewer-prefs'

interface ViewerPrefs {
  wordWrap: boolean
  jsonRawMode: boolean
}

function load(): ViewerPrefs {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    if (raw) return { ...defaults(), ...JSON.parse(raw) }
  } catch { /* ignore */ }
  return defaults()
}

function defaults(): ViewerPrefs {
  return { wordWrap: true, jsonRawMode: false }
}

function persist(prefs: ViewerPrefs) {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(prefs))
  } catch { /* quota exceeded, ignore */ }
}

const stored = load()
export const wordWrap = ref(stored.wordWrap)
export const jsonRawMode = ref(stored.jsonRawMode)

watch([wordWrap, jsonRawMode], () => {
  persist({ wordWrap: wordWrap.value, jsonRawMode: jsonRawMode.value })
})
