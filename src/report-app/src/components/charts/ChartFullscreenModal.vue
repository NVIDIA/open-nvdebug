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
  <div>
    <!-- Trigger button -->
    <button @click="open = true" class="nv-btn nv-btn--ghost nv-btn--sm" style="position: absolute; top: 4px; right: 4px; z-index: 1;" title="Fullscreen">
      &#x26F6;
    </button>

    <!-- Fullscreen modal -->
    <Teleport to="body">
      <div v-if="open" @click.self="open = false" @keydown.escape="open = false" tabindex="-1" ref="overlayRef"
        class="nv-modal-overlay nv-modal-overlay--fullscreen">
        <div class="nv-modal nv-modal--fullscreen" @click.stop>
          <div class="nv-modal__header">
            <h3 v-if="title" class="nv-modal__title">{{ title }}</h3>
            <button @click="open = false" class="nv-modal__close">&times;</button>
          </div>
          <div class="nv-modal__body">
            <slot name="fullscreen" />
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Normal view -->
    <div style="position: relative;">
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, nextTick, onUnmounted } from 'vue'

defineProps<{
  title?: string
}>()

const open = ref(false)
const overlayRef = ref<HTMLElement>()

watch(open, async (val) => {
  if (val) {
    // Lock page scroll: the modal covers the full viewport, so background
    // scrolling would be invisible and lose the user's place.
    document.body.style.overflow = 'hidden'
    await nextTick()
    overlayRef.value?.focus()
  } else {
    document.body.style.overflow = ''
  }
})

onUnmounted(() => {
  if (open.value) document.body.style.overflow = ''
})
</script>
