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
  <div class="nv-flow" role="list">
    <template v-for="(step, index) in steps" :key="index">
      <div
        :class="['nv-flow__step', { 'nv-flow__step--highlight': step.highlighted }]"
        role="listitem"
      >
        {{ step.label }}
        <small v-if="step.sublabel" class="nv-flow__sublabel">{{ step.sublabel }}</small>
      </div>
      <span v-if="index < steps.length - 1" class="nv-flow__arrow" aria-hidden="true">&#10230;</span>
    </template>
  </div>
</template>

<script setup lang="ts">
export interface FlowStep {
  label: string
  sublabel?: string
  highlighted?: boolean
}

defineProps<{
  steps: FlowStep[]
}>()
</script>
