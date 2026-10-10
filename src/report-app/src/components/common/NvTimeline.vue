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
  <div class="nv-timeline" role="list">
    <div
      v-for="(item, index) in items"
      :key="item.id ?? index"
      class="nv-timeline__event"
      role="listitem"
    >
      <span :class="['nv-timeline__dot', `nv-timeline__dot--${item.severity ?? 'neutral'}`]" />
      <div class="nv-timeline__header">
        <span v-if="item.time" class="nv-timeline__time">{{ item.time }}</span>
        <span v-if="item.source" class="nv-timeline__source">{{ item.source }}</span>
      </div>
      <div class="nv-timeline__desc">
        <slot :name="`event-${index}`" :item="item">
          {{ item.description }}
        </slot>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
export interface TimelineItem {
  id?: string | number
  time?: string
  source?: string
  description?: string
  severity?: 'success' | 'warning' | 'error' | 'info' | 'neutral'
}

defineProps<{
  items: TimelineItem[]
}>()
</script>
