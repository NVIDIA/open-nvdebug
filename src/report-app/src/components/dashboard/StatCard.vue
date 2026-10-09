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
    @click="$emit('click')"
    :class="['nv-stat', `nv-stat--${color}`, clickable && 'nv-stat--clickable']"
  >
    <div class="nv-stat__label">{{ label }}</div>
    <div class="nv-stat__value">{{ value }}</div>
    <div v-if="subtitle" class="nv-stat__subtitle">{{ subtitle }}</div>
  </div>
</template>

<script setup lang="ts">
const props = withDefaults(defineProps<{
  label: string
  value: string | number
  subtitle?: string
  color?: string
  gradient?: string
  clickable?: boolean
}>(), {
  color: 'green',
  clickable: false,
})

defineEmits<{ click: [] }>()
</script>
