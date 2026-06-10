<template>
  <Transition name="nprogress">
    <div v-if="visible" class="nav-progress">
      <div class="nav-progress__bar" :style="{ width: `${progress}%` }"></div>
    </div>
  </Transition>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const visible = ref(false)
const progress = ref(0)
let timer: ReturnType<typeof setInterval> | null = null
let hideTimer: ReturnType<typeof setTimeout> | null = null

function start() {
  if (hideTimer) { clearTimeout(hideTimer); hideTimer = null }
  progress.value = 10
  visible.value = true
  timer = setInterval(() => {
    if (progress.value < 90) {
      progress.value += Math.random() * 15
      if (progress.value > 90) progress.value = 90
    }
  }, 200)
}

function done() {
  if (timer) { clearInterval(timer); timer = null }
  progress.value = 100
  hideTimer = setTimeout(() => {
    visible.value = false
    progress.value = 0
  }, 300)
}

let removeBeforeEach: (() => void) | null = null
let removeAfterEach: (() => void) | null = null

onMounted(() => {
  removeBeforeEach = router.beforeEach(() => { start() })
  removeAfterEach = router.afterEach(() => { done() })
})

onUnmounted(() => {
  removeBeforeEach?.()
  removeAfterEach?.()
  if (timer) clearInterval(timer)
  if (hideTimer) clearTimeout(hideTimer)
})
</script>

<style scoped>
.nav-progress {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  z-index: 10000;
  pointer-events: none;
}
.nav-progress__bar {
  height: 100%;
  background: var(--nv-accent, #76b900);
  box-shadow: 0 0 8px var(--nv-accent, #76b900);
  transition: width 0.2s ease;
  border-radius: 0 2px 2px 0;
}

.nprogress-enter-active { transition: opacity 0.1s; }
.nprogress-leave-active { transition: opacity 0.4s; }
.nprogress-enter-from,
.nprogress-leave-to { opacity: 0; }
</style>
