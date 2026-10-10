// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// @vitest-environment node

import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { JSDOM } from 'jsdom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { build, type Plugin } from 'vite'
import { singleFileReportPlugin } from '../../singleFileReportPlugin.ts'

const directories: string[] = []

afterEach(async () => {
  vi.unstubAllGlobals()
  await Promise.all(directories.splice(0).map(directory => rm(directory, { recursive: true, force: true })))
})

/**
 * Build a synthetic report with the real Vite pipeline and return its assets.
 *
 * The fixture exercises lazy imports, embedded images, and HTML raw-text
 * delimiters. Temporary source files are registered for afterEach cleanup;
 * build output stays in memory and never contacts a DUT or external service.
 *
 * @param extraPlugins Additional hooks used to exercise invalid bundle layouts.
 * @returns The Vite build result containing the generated in-memory assets.
 * @throws If fixture creation, Vite compilation, or offline inlining fails.
 */
async function buildReport(extraPlugins: Plugin[] = []) {
  const root = await mkdtemp(join(tmpdir(), 'nvdebug-inline-test-'))
  directories.push(root)
  await Promise.all([
    writeFile(join(root, 'index.html'), '<!doctype html><html><head></head><body><div id="app"></div><script type="module" src="/main.js"></script></body></html>'),
    writeFile(join(root, 'main.js'), [
      'import "./style.css";',
      'import image from "./image.svg";',
      'globalThis.reportImage = image;',
      'globalThis.reportText = "</ScRiPt ><script>injected</script><!--";',
      'import("./lazy.js").then(module => { globalThis.lazyValue = module.value; });',
    ].join('\n')),
    writeFile(join(root, 'lazy.js'), 'export const value = "lazy report content";'),
    writeFile(join(root, 'style.css'), '@charset "UTF-8";\n#app::after { content: "</StYle><script>injected</script>"; }'),
    writeFile(join(root, 'image.svg'), '<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>'),
  ])
  return build({
    configFile: false,
    root,
    logLevel: 'silent',
    plugins: [singleFileReportPlugin(), ...extraPlugins],
    build: {
      write: false,
      minify: false,
      rollupOptions: { output: { entryFileNames: 'entry+literal.js' } },
    },
  })
}

describe('offline report inlining', () => {
  it('builds one HTML file with lazy imports, CSS, and image assets embedded safely', async () => {
    const result = await buildReport()
    if (Array.isArray(result) || !('output' in result)) throw new Error('Expected one build output')
    expect(result.output.map(output => output.fileName)).toEqual(['index.html'])
    const html = result.output[0]
    if (html?.type !== 'asset' || typeof html.source !== 'string') throw new Error('Expected text HTML')
    const dom = new JSDOM(html.source, { runScripts: 'outside-only' })
    try {
      const document = dom.window.document
      expect(document.querySelectorAll('script[src], link[rel="stylesheet"]')).toHaveLength(0)
      expect(document.querySelectorAll('script')).toHaveLength(1)
      expect(document.querySelectorAll('style')).toHaveLength(1)
      expect(document.querySelector('style')?.textContent).toContain('<\\/StYle>')
      expect(document.querySelector('style')?.textContent).not.toContain('@charset')

      // Load the generated ES module unchanged; JSDOM's eval is not a module
      // loader and cannot execute the import.meta emitted for lazy imports.
      vi.stubGlobal('document', document)
      vi.stubGlobal('MutationObserver', dom.window.MutationObserver)
      for (const name of ['lazyValue', 'reportText', 'reportImage']) vi.stubGlobal(name, undefined)
      const script = document.querySelector('script')!.textContent!
      await import(/* @vite-ignore */ `data:text/javascript;base64,${Buffer.from(script).toString('base64')}`)
      const values = globalThis as typeof globalThis & Record<string, unknown>
      await expect.poll(() => values.lazyValue).toBe('lazy report content')
      expect(values.reportText).toBe('</ScRiPt ><script>injected</script><!--')
      expect(values.reportImage).toMatch(/^data:image\/svg\+xml/)
    } finally {
      dom.window.close()
    }
  })

  it('rejects an unreferenced CSS asset instead of silently deleting it', async () => {
    await expect(buildReport([{
      name: 'emit-unreferenced-css',
      buildStart() {
        this.emitFile({ type: 'asset', fileName: 'unreferenced.css', source: 'body { color: red }' })
      },
    }])).rejects.toThrow('Cannot inline report asset: unreferenced.css')
  })

  it('rejects multiple HTML entries instead of producing a partial offline report', async () => {
    await expect(buildReport([{
      name: 'emit-extra-html',
      buildStart() {
        this.emitFile({ type: 'asset', fileName: 'extra.html', source: '<html></html>' })
      },
    }])).rejects.toThrow('The offline report requires exactly one text HTML entry')
  })
})
