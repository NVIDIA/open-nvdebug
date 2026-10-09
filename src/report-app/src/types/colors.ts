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

export const STATUS_COLORS: Record<string, string> = {
  success: 'var(--nv-success)',
  degraded: 'var(--nv-warning)',
  error: 'var(--nv-error)',
  partial: 'var(--nv-warning)',
  skipped: 'var(--nv-skipped)',
  cancelled: 'var(--nv-warning)',
  canceled: 'var(--nv-warning)',
  running: 'var(--nv-info)',
  pending: 'var(--nv-text-tertiary)',
  not_ran: 'var(--nv-text-tertiary)',
  unknown: 'var(--nv-text-tertiary)',
  complete: 'var(--nv-success)',
}

export const STATUS_BG_COLORS: Record<string, string> = {
  success: 'var(--nv-success-muted)',
  degraded: 'var(--nv-warning-muted)',
  error: 'var(--nv-error-muted)',
  partial: 'var(--nv-warning-muted)',
  skipped: 'var(--nv-skipped-muted)',
  cancelled: 'var(--nv-warning-muted)',
  canceled: 'var(--nv-warning-muted)',
  running: 'var(--nv-info-muted)',
  pending: 'var(--nv-bg-tertiary)',
  not_ran: 'var(--nv-bg-tertiary)',
  unknown: 'var(--nv-bg-tertiary)',
  complete: 'var(--nv-success-muted)',
}

export const SERVICE_COLORS: Record<string, string> = {
  redfish: 'var(--nv-service-redfish)',
  ssh: 'var(--nv-service-ssh)',
  ipmi: 'var(--nv-service-ipmi)',
  health_check: 'var(--nv-service-health-check)',
  host: 'var(--nv-service-host)',
  bmc: 'var(--nv-service-bmc)',
  preflight: 'var(--nv-service-preflight)',
}
