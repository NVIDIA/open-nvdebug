import { ref } from 'vue'

export type ToastVariant = 'success' | 'error' | 'info'

export interface ToastItem {
  id: number
  message: string
  variant: ToastVariant
}

let nextId = 0
export const toasts = ref<ToastItem[]>([])

export function showToast(message: string, variant: ToastVariant = 'info') {
  const id = nextId++
  toasts.value.push({ id, message, variant })
  setTimeout(() => {
    toasts.value = toasts.value.filter(t => t.id !== id)
  }, 3000)
}

export function dismissToast(id: number) {
  toasts.value = toasts.value.filter(t => t.id !== id)
}
