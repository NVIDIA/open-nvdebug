<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

<template>
  <span :class="['nv-badge', badgeClass]">
    {{ label }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  status: string
}>()

const STATUS_ALIASES: Record<string, string> = {
  complete: 'success',
  passed: 'success',
  failed: 'error',
  interrupted: 'warning',
  cancelled: 'warning',
  canceled: 'warning',
  notran: 'not_ran',
}

const canonicalStatus = computed(() => props.status?.trim().toLowerCase() || 'unknown')

const normalizedStatus = computed(() => {
  return STATUS_ALIASES[canonicalStatus.value] ?? canonicalStatus.value
})

const label = computed(() => {
  const labels: Record<string, string> = {
    success: 'Success',
    degraded: 'Degraded',
    error: 'Error',
    partial: 'Partial',
    skipped: 'Skipped',
    not_ran: 'Not Ran',
    running: 'Running',
    pending: 'Pending',
    incomplete: 'Incomplete',
    unknown: 'Unknown',
    pass: 'Pass',
    fail: 'Fail',
    warning: 'Warning',
    skip: 'Skip',
    na: 'N/A',
    complete: 'Success',
    interrupted: 'Interrupted',
    cancelled: 'Cancelled',
    canceled: 'Cancelled',
  }
  return labels[canonicalStatus.value] || labels[normalizedStatus.value] || props.status
})

const badgeClass = computed(() => `nv-badge--${normalizedStatus.value}`)
</script>
