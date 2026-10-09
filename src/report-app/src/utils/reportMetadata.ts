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

import type { AccessPath, SecurityModeMetadata } from '@/types/manifest'

const ACCESS_PATH_LABELS: Record<AccessPath, string> = {
  redfish: 'Redfish',
  host_ssh: 'Host SSH',
  bmc_ssh: 'BMC SSH',
  ipmi: 'IPMI',
  composite: 'Composite',
  unknown: 'Unknown',
}

export function formatAccessPath(accessPath: AccessPath): string {
  return ACCESS_PATH_LABELS[accessPath]
}

export function formatSecurityModeValue(metadata: SecurityModeMetadata): string {
  if (metadata.status !== 'reported' || metadata.value === null) return 'Not reported'
  return String(metadata.value)
}

export function formatSecurityModeSource(metadata: SecurityModeMetadata): string {
  if (metadata.status !== 'reported' || !metadata.source) return 'No explicit source'
  return metadata.source
}
