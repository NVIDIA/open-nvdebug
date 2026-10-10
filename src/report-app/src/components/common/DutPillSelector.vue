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
  <div class="pill-selector" role="listbox" :aria-multiselectable="multiple">
    <button
      v-for="option in options"
      :key="option.id"
      class="pill-selector__pill"
      :class="{
        'pill-selector__pill--selected': isSelected(option.id),
        'pill-selector__pill--disabled': isDisabled(option.id),
      }"
      role="option"
      :aria-selected="isSelected(option.id)"
      :disabled="isDisabled(option.id)"
      @click="toggle(option.id)"
    >
      <span v-if="option.status" class="pill-selector__dot" :style="{ background: statusColor(option.status) }"></span>
      {{ option.label }}
    </button>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

export interface PillOption {
  id: string
  label: string
  status?: string
}

const props = withDefaults(defineProps<{
  options: PillOption[]
  modelValue: string | string[]
  multiple?: boolean
  max?: number
}>(), {
  multiple: false,
  max: 0,
})

const emit = defineEmits<{
  'update:modelValue': [value: string | string[]]
}>()

const selectedSet = computed(() => {
  if (Array.isArray(props.modelValue)) return new Set(props.modelValue)
  return new Set(props.modelValue ? [props.modelValue] : [])
})

function isSelected(id: string): boolean {
  return selectedSet.value.has(id)
}

function isDisabled(id: string): boolean {
  if (isSelected(id)) return false
  if (props.multiple && props.max > 0 && selectedSet.value.size >= props.max) return true
  return false
}

function toggle(id: string) {
  if (props.multiple) {
    const current = Array.isArray(props.modelValue) ? [...props.modelValue] : []
    const idx = current.indexOf(id)
    if (idx >= 0) {
      current.splice(idx, 1)
    } else {
      if (props.max > 0 && current.length >= props.max) return
      current.push(id)
    }
    emit('update:modelValue', current)
  } else {
    emit('update:modelValue', isSelected(id) ? '' : id)
  }
}

const STATUS_COLORS: Record<string, string> = {
  success: 'var(--nv-success)',
  degraded: 'var(--nv-warning)',
  error: 'var(--nv-error)',
  partial: 'var(--nv-warning)',
  skipped: 'var(--nv-skipped)',
  not_ran: 'var(--nv-text-disabled)',
}

function statusColor(status: string): string {
  return STATUS_COLORS[status] ?? 'var(--nv-text-tertiary)'
}
</script>

<style scoped>
.pill-selector {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.pill-selector__pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 14px;
  font-size: 0.75rem;
  font-weight: 500;
  font-family: var(--nv-font-family);
  color: var(--nv-text-secondary);
  background: var(--nv-glass-bg-light);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-full);
  cursor: pointer;
  transition: all 0.15s ease;
  white-space: nowrap;
  user-select: none;
}

.pill-selector__pill:hover:not(:disabled) {
  background: var(--nv-bg-hover);
  border-color: var(--nv-border-hover);
  color: var(--nv-text-primary);
}

.pill-selector__pill--selected {
  background: var(--nv-accent-muted);
  border-color: var(--nv-accent);
  color: var(--nv-accent);
  font-weight: 600;
}

.pill-selector__pill--selected:hover:not(:disabled) {
  background: var(--nv-accent-muted);
  border-color: var(--nv-accent-hover);
}

.pill-selector__pill--disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

.pill-selector__dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}
</style>
