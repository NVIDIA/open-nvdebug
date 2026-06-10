export interface WorkerLike {
  postMessage(data: any): void
  onmessage: ((event: MessageEvent) => void) | null
  terminate(): void
}

/**
 * Creates an inline Blob URL worker, or falls back to main-thread execution
 * if the browser blocks it (Firefox under file://).
 */
export function createInlineWorker(workerCode: string, handler?: (data: any) => any): WorkerLike {
  try {
    const blob = new Blob([workerCode], { type: 'application/javascript' })
    const url = URL.createObjectURL(blob)
    const worker = new Worker(url)
    // Clean up blob URL after worker loads
    worker.addEventListener('error', () => URL.revokeObjectURL(url), { once: true })
    return worker
  } catch (e) {
    // Firefox file:// — fall back to main thread
    return new MainThreadFallback(handler)
  }
}

class MainThreadFallback implements WorkerLike {
  onmessage: ((event: MessageEvent) => void) | null = null
  private handler: (data: any) => any

  constructor(handler?: (data: any) => any) {
    this.handler = handler ?? ((data) => data)
  }

  postMessage(data: any): void {
    // Process in idle callbacks to avoid blocking UI
    if (typeof requestIdleCallback !== 'undefined') {
      requestIdleCallback(() => this.process(data))
    } else {
      setTimeout(() => this.process(data), 0)
    }
  }

  private process(data: any): void {
    try {
      const result = this.handler(data)
      this.onmessage?.({ data: result } as MessageEvent)
    } catch (e) {
      this.onmessage?.({ data: { error: String(e) } } as MessageEvent)
    }
  }

  terminate(): void {
    this.onmessage = null
  }
}
