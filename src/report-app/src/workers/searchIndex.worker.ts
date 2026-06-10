/**
 * Search index worker — searches file content for a pattern.
 *
 * Input: { content: string, query: string, filePath: string, regex?: boolean }
 * Output: { results: Array<{ filePath: string, lineNumber: number, lineContent: string, matchStart: number, matchEnd: number }> }
 */

export function handleMessage(data: {
  content: string
  query: string
  filePath: string
  regex?: boolean
}): {
  results: Array<{
    filePath: string
    lineNumber: number
    lineContent: string
    matchStart: number
    matchEnd: number
  }>
} {
  const { content, query, filePath, regex } = data
  const results: Array<{
    filePath: string
    lineNumber: number
    lineContent: string
    matchStart: number
    matchEnd: number
  }> = []

  const lines = content.split('\n')
  const pattern = regex ? new RegExp(query, 'gi') : null

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (regex && pattern) {
      pattern.lastIndex = 0
      const match = pattern.exec(line)
      if (match) {
        results.push({
          filePath,
          lineNumber: i + 1,
          lineContent: line.slice(0, 200),
          matchStart: match.index,
          matchEnd: match.index + match[0].length,
        })
      }
    } else {
      const idx = line.toLowerCase().indexOf(query.toLowerCase())
      if (idx >= 0) {
        results.push({
          filePath,
          lineNumber: i + 1,
          lineContent: line.slice(0, 200),
          matchStart: idx,
          matchEnd: idx + query.length,
        })
      }
    }
  }

  return { results }
}

if (typeof self !== 'undefined' && typeof (self as any).onmessage !== 'undefined') {
  self.onmessage = (event: MessageEvent) => {
    const result = handleMessage(event.data)
    self.postMessage(result)
  }
}
