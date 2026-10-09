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

import type { RouteLocationRaw } from 'vue-router'

function routeIdentifier(value: unknown): string {
  return String(value)
}

export function dutRoute(dutId: unknown, highlight?: unknown): RouteLocationRaw {
  return {
    name: 'dut',
    params: { dutId: routeIdentifier(dutId) },
    ...(highlight === undefined || highlight === null || highlight === ''
      ? {}
      : { query: { highlight: routeIdentifier(highlight) } }),
  }
}

export function dutPreflightRoute(dutId: unknown): RouteLocationRaw {
  return {
    name: 'preflight',
    params: { dutId: routeIdentifier(dutId) },
  }
}

export function dutFirmwareRoute(dutId: unknown): RouteLocationRaw {
  return {
    name: 'firmware',
    params: { dutId: routeIdentifier(dutId) },
  }
}

export function dutProfileRoute(dutId: unknown): RouteLocationRaw {
  return {
    name: 'dut-profile',
    params: { dutId: routeIdentifier(dutId) },
  }
}

export function collectorGroupRoute(dutId: unknown, group: unknown): RouteLocationRaw {
  return {
    name: 'collector-group',
    params: {
      dutId: routeIdentifier(dutId),
      group: routeIdentifier(group),
    },
  }
}

export function collectorDetailRoute(
  dutId: unknown,
  group: unknown,
  collectorId: unknown,
): RouteLocationRaw {
  return {
    name: 'collector-detail',
    params: {
      dutId: routeIdentifier(dutId),
      group: routeIdentifier(group),
      collectorId: routeIdentifier(collectorId),
    },
  }
}
