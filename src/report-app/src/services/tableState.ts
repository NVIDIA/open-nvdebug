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

export interface TableState {
  searchText: string
  sortKey: string
  sortDir: 'asc' | 'desc'
  currentPage: number
  pageSize: number
  density: 'compact' | 'comfortable' | 'spacious'
  visibleColumns: string[]
  columnFilters: Array<[string, string]>
}

// Each report owns a router. Retain UI settings, never report rows, in a bounded
// in-memory history. Closing the report also releases any entered search text.
const sessions = new WeakMap<object, Map<string, TableState>>()
const MAX_TABLE_STATES = 100

export function readTableState(owner: object | null, key: string): TableState | undefined {
  return owner ? sessions.get(owner)?.get(key) : undefined
}

export function saveTableState(owner: object | null, key: string, state: TableState): void {
  if (!owner) return
  let tables = sessions.get(owner)
  if (!tables) {
    tables = new Map()
    sessions.set(owner, tables)
  }
  tables.delete(key)
  tables.set(key, state)
  if (tables.size > MAX_TABLE_STATES) tables.delete(tables.keys().next().value!)
}
