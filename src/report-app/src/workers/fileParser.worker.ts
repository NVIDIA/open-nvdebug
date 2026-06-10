/**
 * File parser worker — extracts line boundaries from large text content.
 * Used for virtual viewport rendering of large files.
 *
 * Input: { content: string, chunkSize?: number }
 * Output: { lineCount: number, lineOffsets: number[], complete: boolean }
 */

export function handleMessage(data: { content: string; chunkSize?: number }): {
  lineCount: number
  lineOffsets: number[]
  complete: boolean
} {
  const { content, chunkSize = 50000 } = data
  const lineOffsets: number[] = [0]

  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') {
      lineOffsets.push(i + 1)
    }
  }

  return {
    lineCount: lineOffsets.length,
    lineOffsets,
    complete: true,
  }
}

// Worker entry point (runs when loaded as a Blob URL worker)
if (typeof self !== 'undefined' && typeof (self as any).onmessage !== 'undefined') {
  self.onmessage = (event: MessageEvent) => {
    const result = handleMessage(event.data)
    self.postMessage(result)
  }
}
