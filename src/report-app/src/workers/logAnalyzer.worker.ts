/**
 * Log analyzer worker — extracts levels, components, and timestamps from structured logs.
 *
 * Input: { content: string }
 * Output: { levels: string[], components: string[], lineCount: number, errorCount: number, warnCount: number }
 */

const LOG_PATTERN = /\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)/

export function handleMessage(data: { content: string }): {
  levels: string[]
  components: string[]
  lineCount: number
  errorCount: number
  warnCount: number
} {
  const levels = new Set<string>()
  const components = new Set<string>()
  let lineCount = 0
  let errorCount = 0
  let warnCount = 0

  const lines = data.content.split('\n')
  for (const line of lines) {
    lineCount++
    const match = line.match(LOG_PATTERN)
    if (match) {
      const level = match[2]
      const component = match[3]
      levels.add(level)
      components.add(component)
      if (level === 'ERROR') errorCount++
      if (level === 'WARNING') warnCount++
    }
  }

  return {
    levels: [...levels].sort(),
    components: [...components].sort(),
    lineCount,
    errorCount,
    warnCount,
  }
}

if (typeof self !== 'undefined' && typeof (self as any).onmessage !== 'undefined') {
  self.onmessage = (event: MessageEvent) => {
    const result = handleMessage(event.data)
    self.postMessage(result)
  }
}
