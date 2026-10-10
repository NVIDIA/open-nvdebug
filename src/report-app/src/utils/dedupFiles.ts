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

import type { FileRef } from '@/types/manifest'

export function dedupFiles(files: FileRef[]): FileRef[] {
  const seen = new Set<string>()
  return files.filter(f => {
    if (seen.has(f.path)) return false
    seen.add(f.path)
    return true
  })
}

/** Return whether a file is collector diagnostic metadata rather than output. */
export function isDiagnosticFilePath(path: string): boolean {
  const parts = path.replace(/\\/g, '/').split('/').filter(Boolean)
  if (parts.slice(0, -1).some(part => part.toLowerCase() === 'diagnostic')) {
    return true
  }

  const basename = (parts[parts.length - 1] ?? '').toLowerCase()
  return [
    'diagnostic_request_',
    'diagnostic_requests_',
    'diagnostic_response_',
    'diagnostic_responses_',
    'diagnostic_error_',
    'diagnostic_errors_',
    'task_completions_',
    'task_status_updates_',
    'taskservice_snapshot_',
    'redfish_request_response_log',
    'host_execution_log',
  ].some(prefix => basename.startsWith(prefix))
}

export function partitionCollectorFiles(files: FileRef[]): {
  artifacts: FileRef[]
  diagnostics: FileRef[]
} {
  const artifacts: FileRef[] = []
  const diagnostics: FileRef[] = []
  for (const file of files) {
    (isDiagnosticFilePath(file.path) ? diagnostics : artifacts).push(file)
  }
  return { artifacts, diagnostics }
}
