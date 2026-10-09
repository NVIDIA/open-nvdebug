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
  <div
    class="nv-skeleton"
    :style="{
      height: computedHeight,
      width: computedWidth,
      borderRadius: variant === 'card' ? 'var(--nv-radius-lg)' : undefined,
    }"
  />
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  variant?: 'card' | 'table-row' | 'chart' | 'text-block'
  width?: string
  height?: string
}>(), {
  variant: 'text-block',
})

const computedHeight = computed(() => {
  if (props.height) return props.height
  switch (props.variant) {
    case 'card': return '120px'
    case 'table-row': return '40px'
    case 'chart': return '300px'
    case 'text-block': return '16px'
    default: return '16px'
  }
})

const computedWidth = computed(() => props.width || '100%')
</script>
