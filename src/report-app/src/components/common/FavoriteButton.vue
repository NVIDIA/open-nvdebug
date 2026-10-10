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
  <button
    @click="store.toggleFavorite(itemPath)"
    :class="['nv-btn', 'nv-btn--ghost', 'nv-btn--sm']"
    :title="isFav ? 'Remove from favorites' : 'Add to favorites'"
  >
    {{ isFav ? '\u2605' : '\u2606' }}
  </button>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAnnotationsStore } from '@/stores/annotations'

const props = defineProps<{ itemPath: string }>()
const store = useAnnotationsStore()
const isFav = computed(() => store.isFavorite(props.itemPath))
</script>
