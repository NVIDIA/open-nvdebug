/**
 * JSON parser worker — parses large JSON strings without blocking UI.
 *
 * Input: { content: string }
 * Output: { data: any, error?: string }
 */

export function handleMessage(data: { content: string }): {
  data: any
  error?: string
} {
  try {
    const parsed = JSON.parse(data.content)
    return { data: parsed }
  } catch (e) {
    return { data: null, error: e instanceof Error ? e.message : String(e) }
  }
}

if (typeof self !== 'undefined' && typeof (self as any).onmessage !== 'undefined') {
  self.onmessage = (event: MessageEvent) => {
    const result = handleMessage(event.data)
    self.postMessage(result)
  }
}
