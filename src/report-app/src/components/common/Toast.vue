<template>
  <Teleport to="body">
    <div class="toast-container" aria-live="polite">
      <TransitionGroup name="toast">
        <div
          v-for="t in toasts"
          :key="t.id"
          :class="['toast-item', `toast-item--${t.variant}`]"
          @click="dismissToast(t.id)"
        >
          <svg v-if="t.variant === 'success'" class="toast-item__icon" width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0zm3.78 5.28-4.5 5a.75.75 0 0 1-1.06.02l-2-2a.75.75 0 1 1 1.06-1.06l1.46 1.46 3.97-4.42a.75.75 0 1 1 1.07 1z"/></svg>
          <svg v-else-if="t.variant === 'error'" class="toast-item__icon" width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0zm1 12H7v-2h2v2zm0-3H7V4h2v5z"/></svg>
          <svg v-else class="toast-item__icon" width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0zm1 12H7V7h2v5zm0-6H7V4h2v2z"/></svg>
          <span class="toast-item__msg">{{ t.message }}</span>
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { toasts, dismissToast } from '@/composables/useToast'
</script>

<style scoped>
.toast-container {
  position: fixed;
  bottom: 16px;
  right: 16px;
  z-index: 1500;
  display: flex;
  flex-direction: column-reverse;
  gap: 8px;
  pointer-events: none;
  max-width: 360px;
}

.toast-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 16px;
  border-radius: 8px;
  background: var(--nv-glass-bg-dense);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--nv-glass-border);
  color: var(--nv-text-strong);
  font-size: 0.8125rem;
  font-weight: 500;
  cursor: pointer;
  pointer-events: auto;
  box-shadow: var(--nv-glass-shadow);
}
.toast-item--success { border-left: 3px solid var(--nv-success); }
.toast-item--success .toast-item__icon { color: var(--nv-success); }
.toast-item--error { border-left: 3px solid var(--nv-error); }
.toast-item--error .toast-item__icon { color: var(--nv-error); }
.toast-item--info { border-left: 3px solid var(--nv-info); }
.toast-item--info .toast-item__icon { color: var(--nv-info); }

.toast-item__icon { flex-shrink: 0; }
.toast-item__msg { flex: 1; }

.toast-enter-active { transition: transform 0.25s ease, opacity 0.25s ease; }
.toast-leave-active { transition: transform 0.2s ease, opacity 0.2s ease; }
.toast-enter-from { transform: translateX(100%); opacity: 0; }
.toast-leave-to { transform: translateX(40px); opacity: 0; }
</style>
