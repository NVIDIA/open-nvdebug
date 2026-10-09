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

// The inlining logic is adapted from vite-plugin-singlefile 2.3.2:
// https://github.com/richardtallent/vite-plugin-singlefile
// NVDebug always inlines every JS/CSS asset, so this adaptation omits the
// optional glob filtering and its micromatch/braces dependency. It supports
// one HTML entry and fails the build if an emitted JS/CSS asset is not inlined.
// The upstream portions retain the following license:
//
// MIT License
//
// Copyright (c) 2021-present, Richard S. Tallent, II
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import type { Plugin } from 'vite'

/** Inline the report's generated JS and CSS so it can open through file://. */
export function singleFileReportPlugin(): Plugin {
  return {
    name: 'nvdebug:single-file-report',
    enforce: 'post',
    config() {
      return {
        base: './',
        build: {
          assetsInlineLimit: () => true,
          chunkSizeWarningLimit: 100_000_000,
          cssCodeSplit: false,
          assetsDir: '',
          rollupOptions: { output: { codeSplitting: false } },
        },
      }
    },
    generateBundle(_options, bundle) {
      const htmlFiles = Object.values(bundle).filter(output => /\.html?$/i.test(output.fileName))
      const htmlFile = htmlFiles[0]
      if (htmlFiles.length !== 1 || htmlFile?.type !== 'asset' || typeof htmlFile.source !== 'string') {
        this.error('The offline report requires exactly one text HTML entry')
      }

      let html = htmlFile.source
      const inlined: string[] = []
      for (const [name, output] of Object.entries(bundle)) {
        // Filenames are literals, including any regexp metacharacters.
        const filename = output.fileName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        let nextHtml: string
        if (output.type === 'chunk' && /\.[mc]?js$/i.test(name)) {
          const scriptTag = new RegExp(`<script([^>]*?) src="(?:[^"]*?/)?${filename}"([^>]*)></script>`, 'g')
          // HTML raw-text delimiters are case-insensitive, even in JS strings.
          const code = output.code
            .replace(/"?__VITE_PRELOAD__"?/g, 'void 0')
            .replace(/<(\/script\b|!--)/gi, '\\x3C$1')
          nextHtml = html.replace(scriptTag, (_match, before, after) => (
            `<script${before}${after}>${code.trim()}</script>`
          ))
        } else if (output.type === 'asset' && /\.css$/i.test(name)) {
          if (typeof output.source !== 'string') {
            this.error(`The offline report requires text CSS: ${name}`)
          }
          const styleTag = new RegExp(`<link([^>]*?) href="(?:[^"]*?/)?${filename}"([^>]*)>`, 'g')
          const css = output.source
            .replace('@charset "UTF-8";', '')
            .replace(/<\/style\b/gi, delimiter => delimiter.replace('</', '<\\/'))
          nextHtml = html.replace(styleTag, (_match, before, after) => (
            `<style${before}${after}>${css.trim()}</style>`
          ))
        } else {
          continue
        }
        if (nextHtml === html) {
          this.error(`Cannot inline report asset: ${name}`)
        }
        html = nextHtml
        inlined.push(name)
      }

      // Delete assets only after every required replacement has succeeded.
      htmlFile.source = html
      for (const name of inlined) delete bundle[name]
    },
  }
}
