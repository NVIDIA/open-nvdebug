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
