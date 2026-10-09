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
  <Teleport to="body">
    <Transition name="modal">
      <div
        v-if="modelValue"
        class="nv-modal-overlay"
        @click.self="close"
        @keydown.escape="close"
        tabindex="-1"
        ref="overlayRef"
      >
        <div :class="['nv-modal', sizeClass]" @click.stop>
          <div class="nv-modal__header">
            <h3 class="nv-modal__title">{{ title }}</h3>
            <button @click="close" class="nv-modal__close">&times;</button>
          </div>
          <div class="nv-modal__body">
            <slot />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue'

const props = withDefaults(defineProps<{
  modelValue: boolean
  title: string
  maxWidth?: string
}>(), {
  maxWidth: '600px',
})

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
}>()

const overlayRef = ref<HTMLElement>()

const sizeClass = computed(() => {
  switch (props.maxWidth) {
    case '400px': return 'nv-modal--sm'
    case '600px': return 'nv-modal--md'
    case '900px': return 'nv-modal--lg'
    case '1200px': return 'nv-modal--xl'
    default: return 'nv-modal--md'
  }
})

function close() {
  emit('update:modelValue', false)
}

watch(() => props.modelValue, async (open) => {
  if (open) {
    await nextTick()
    overlayRef.value?.focus()
  }
})
</script>
