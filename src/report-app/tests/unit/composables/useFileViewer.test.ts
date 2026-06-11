import { describe, it, expect } from 'vitest'
import { getViewerType, isBinaryContent } from '@/composables/useFileViewer'
import type { FileRef } from '@/types/manifest'

function makeRef(overrides: Partial<FileRef> = {}): FileRef {
  return {
    path: 'DUT_1/redfish/Systems.json',
    size: 1024,
    type: 'json',
    collector_id: 'R1',
    ...overrides,
  }
}

describe('getViewerType', () => {
  it('returns json-tree for json files', () => {
    expect(getViewerType(makeRef({ type: 'json' }))).toBe('json-tree')
  })

  it('returns monaco for text files', () => {
    expect(getViewerType(makeRef({ type: 'text' }))).toBe('monaco')
  })

  it('returns monaco for log files', () => {
    expect(getViewerType(makeRef({ type: 'log', path: 'DUT_1/host/dmesg.log' }))).toBe('monaco')
  })

  it('returns log-viewer for structured logs', () => {
    expect(getViewerType(makeRef({ type: 'text', path: 'DUT_1/nvdebug_runtime_output.txt' }))).toBe('log-viewer')
  })

  it('returns log-viewer for stdout logs', () => {
    expect(getViewerType(makeRef({ type: 'log', path: 'DUT_1/R1_stdout.log' }))).toBe('log-viewer')
  })

  it('returns download for binary files', () => {
    expect(getViewerType(makeRef({ type: 'binary' }))).toBe('download')
  })

  it('returns download for huge files', () => {
    expect(getViewerType(makeRef({ size: 300_000_000 }))).toBe('download')
  })

  it('respects viewer_hint over type', () => {
    expect(getViewerType(makeRef({ type: 'text', viewer_hint: 'log-viewer' }))).toBe('log-viewer')
  })

  it('respects viewer_hint over size', () => {
    expect(getViewerType(makeRef({ size: 300_000_000, viewer_hint: 'monaco' }))).toBe('monaco')
  })
})

describe('isBinaryContent', () => {
  it('returns false for normal text', () => {
    expect(isBinaryContent('hello world')).toBe(false)
  })

  it('returns false for empty string', () => {
    expect(isBinaryContent('')).toBe(false)
  })

  it('returns true for content with many replacement characters', () => {
    const binary = '\uFFFD'.repeat(100) + 'abc'
    expect(isBinaryContent(binary)).toBe(true)
  })

  it('returns false for content with few replacement characters', () => {
    const text = 'hello\uFFFDworld' + 'x'.repeat(100)
    expect(isBinaryContent(text)).toBe(false)
  })
})
