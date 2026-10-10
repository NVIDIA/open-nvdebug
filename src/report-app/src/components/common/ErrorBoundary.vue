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
  <div v-if="error" class="nv-card" style="border-color: var(--nv-error);">
    <p style="color: var(--nv-error); font-weight: 600; margin: 0 0 8px 0;">Something went wrong</p>
    <p style="color: var(--nv-text-secondary); font-size: 0.8125rem; margin: 0 0 12px 0;">{{ error.message }}</p>
    <button @click="retry" class="nv-btn nv-btn--primary">
      Retry
    </button>
  </div>
  <slot v-else />
</template>

<script setup lang="ts">
import { ref, onErrorCaptured } from 'vue'

const error = ref<Error | null>(null)

onErrorCaptured((err) => {
  error.value = err instanceof Error ? err : new Error(String(err))
  return false // prevent propagation
})

function retry() {
  error.value = null
}
</script>
