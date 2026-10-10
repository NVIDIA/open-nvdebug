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

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { singleFileReportPlugin } from './singleFileReportPlugin.ts'
import { resolve } from 'node:path'
import {
  computeReportAppSourceDigest,
  REPORT_APP_SOURCE_META_NAME,
} from './reportAppSourceDigest.mjs'

const reportAppSourceSha256 = computeReportAppSourceDigest(import.meta.dirname)

// The report app is shipped as a single self-contained index.html so it can be
// opened directly from disk via file:// without running a local web server.
// Browsers block ES module / CSS sub-resource loads from file:// origins (origin
// "null" fails CORS), so singleFileReportPlugin inlines all JS/CSS/assets into
// the HTML. codeSplitting: false flattens route-level dynamic imports into a
// single chunk, which the plugin requires.
export default defineConfig({
  plugins: [
    {
      name: 'nvdebug-report-app-source-provenance',
      transformIndexHtml: {
        order: 'pre',
        handler: () => [
          {
            tag: 'meta',
            attrs: {
              name: REPORT_APP_SOURCE_META_NAME,
              content: reportAppSourceSha256,
            },
            injectTo: 'head-prepend',
          },
        ],
      },
    },
    vue(),
    tailwindcss(),
    singleFileReportPlugin(),
    {
      name: 'nvdebug-report-splash-first',
      enforce: 'post',
      transformIndexHtml: {
        order: 'post',
        handler(html) {
          // Vite hoists the entry script and stylesheet into <head>. Move
          // those generated tags after the splash before singlefile inlines
          // their large contents, so even a partially received page can paint.
          const assets: string[] = []
          const withoutAssets = html.replace(
            /<script\b[^>]*\btype="module"[^>]*>[\s\S]*?<\/script>|<link\b[^>]*\brel="stylesheet"[^>]*>/gu,
            asset => { assets.push(asset); return '' },
          )
          return withoutAssets.replace('</body>', `${assets.join('\n')}\n  </body>`)
        },
      },
    },
  ],
  base: './',
  resolve: {
    alias: [
      { find: '@', replacement: resolve(import.meta.dirname, 'src') },
      // Monaco 0.52 exposes a legacy `module` field but no `main` or `exports`.
      // Pin the bare import to its full ESM entry so Vite 8 resolves it
      // consistently in both Vitest and the single-file production bundle.
      {
        find: /^monaco-editor$/,
        replacement: resolve(
          import.meta.dirname,
          'node_modules/monaco-editor/esm/vs/editor/editor.main.js',
        ),
      },
    ],
  },
  build: {
    assetsInlineLimit: 100 * 1024 * 1024,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        codeSplitting: false,
        manualChunks: undefined,
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    include: ['tests/unit/**/*.test.ts'],
    exclude: ['tests/e2e/**'],
    coverage: {
      provider: 'v8',
      all: true,
      include: ['src/**/*.{ts,vue}'],
      reporter: ['text', 'json-summary', 'html', 'cobertura'],
      thresholds: {
        statements: 53,
        branches: 47,
        functions: 46,
        lines: 56,
      },
    },
  },
})
