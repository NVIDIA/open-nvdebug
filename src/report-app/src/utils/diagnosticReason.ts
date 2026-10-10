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

const ERROR_SECTION = /(?:HTTP|Device|Other) Errors:/
const ERROR_SECTION_GLOBAL = /\s*((?:HTTP|Device|Other) Errors:)\s*/g

/**
 * Restore display-only line structure from the canonical single-line reason.
 * The returned text is never used for copy/export or written back to the model.
 */
export function formatDiagnosticReasonForDisplay(reason: string): string | null {
  if (!ERROR_SECTION.test(reason) || !reason.includes('•')) return null

  const formatted = reason
    .replace(ERROR_SECTION_GLOBAL, '\n$1\n')
    .replace(/\s*•\s*/g, '\n• ')
    .replace(/:\s+-\s+/g, ':\n  - ')
    .replace(/\s+(?=(?:HTTP|Device|Other) Errors:)/g, '\n')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()

  return formatted.includes('\n') ? formatted : null
}
