<template>
  <Teleport to="body">
    <div v-if="visible" class="nv-modal-overlay" style="z-index: 3000;" @click="nextOrClose">
      <!-- Tooltip -->
      <div class="nv-modal nv-modal--sm" style="border: 2px solid var(--nv-accent);" @click.stop>
        <div class="nv-modal__body">
          <h3 style="margin: 0 0 8px; color: var(--nv-accent); font-size: 1rem;">{{ currentStep.title }}</h3>
          <p style="margin: 0 0 16px; color: var(--nv-text-primary); font-size: 0.8125rem; line-height: 1.5;">{{ currentStep.description }}</p>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 0.75rem; color: var(--nv-text-secondary);">{{ stepIndex + 1 }} / {{ steps.length }}</span>
            <span style="flex: 1;" />
            <button v-if="stepIndex > 0" @click.stop="stepIndex--" class="nv-btn nv-btn--sm">Previous</button>
            <button @click.stop="nextOrClose" class="nv-btn nv-btn--primary nv-btn--sm">
              {{ stepIndex < steps.length - 1 ? 'Next' : 'Done' }}
            </button>
            <button @click.stop="dismiss" class="nv-btn nv-btn--ghost nv-btn--sm">Skip Tour</button>
          </div>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'

const TOUR_KEY = 'nv-tour-completed'

const visible = ref(false)
const stepIndex = ref(0)

const steps = [
  { title: 'Welcome to NVDebug Reports', description: 'This is an interactive report viewer for your diagnostic collection. Navigate through DUTs, collectors, and files with full search and analysis tools.' },
  { title: 'Dashboard', description: 'The dashboard shows an overview of your collection — status cards, charts, and a DUT table. Click any card to drill down.' },
  { title: 'Search (Ctrl+K)', description: 'Press Ctrl+K to open the command palette. Search files, collectors, DUTs, or type > for commands.' },
  { title: 'Quick File Open (Ctrl+P)', description: 'Press Ctrl+P to quickly jump to any file in the collection.' },
  { title: 'File Viewers', description: 'Click any file to view it. JSON gets a tree viewer, logs get filtering, and everything else opens in Monaco editor.' },
  { title: 'Theme Toggle', description: 'Press T to toggle between light and dark themes. Your preference is saved.' },
  { title: 'Keyboard Shortcuts', description: 'Press ? at any time to see all available keyboard shortcuts.' },
]

const currentStep = computed(() => steps[stepIndex.value])

function nextOrClose() {
  if (stepIndex.value < steps.length - 1) {
    stepIndex.value++
  } else {
    dismiss()
  }
}

function dismiss() {
  visible.value = false
  localStorage.setItem(TOUR_KEY, 'true')
}

onMounted(() => {
  if (!localStorage.getItem(TOUR_KEY)) {
    // Show tour after a brief delay to let the app render
    setTimeout(() => { visible.value = true }, 1000)
  }
})

defineExpose({
  show() {
    stepIndex.value = 0
    visible.value = true
  },
})
</script>
