<template>
  <Transition name="fade">
    <button
      v-if="visible"
      class="back-to-top"
      @click="scrollToTop"
      aria-label="Back to top"
      title="Back to top"
    >
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="m18 15-6-6-6 6"/>
      </svg>
    </button>
  </Transition>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'

const visible = ref(false)

function onScroll() {
  visible.value = window.scrollY > 400
}

function scrollToTop() {
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

onMounted(() => window.addEventListener('scroll', onScroll, { passive: true }))
onUnmounted(() => window.removeEventListener('scroll', onScroll))
</script>

<style scoped>
.back-to-top {
  position: fixed;
  bottom: 80px;
  right: 24px;
  z-index: 1400;
  width: 40px;
  height: 40px;
  border-radius: 50%;
  border: 1px solid var(--nv-glass-border, rgba(255,255,255,0.08));
  background: var(--nv-glass-bg-dense, rgba(30,30,30,0.95));
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  color: var(--nv-text-primary, #fff);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  transition: background 0.15s ease, transform 0.15s ease;
}
.back-to-top:hover {
  background: var(--nv-bg-hover);
  transform: translateY(-2px);
}
.fade-enter-active, .fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.fade-enter-from, .fade-leave-to {
  opacity: 0;
  transform: translateY(8px);
}
</style>
