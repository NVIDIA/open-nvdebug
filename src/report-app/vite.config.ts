import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { viteSingleFile } from 'vite-plugin-singlefile'
import { resolve } from 'path'

// The report app is shipped as a single self-contained index.html so it can be
// opened directly from disk via file:// without running a local web server.
// Browsers block ES module / CSS sub-resource loads from file:// origins (origin
// "null" fails CORS), so vite-plugin-singlefile inlines all JS/CSS/assets into
// the HTML. codeSplitting: false flattens route-level dynamic imports into a
// single chunk, which the plugin requires.
export default defineConfig({
  plugins: [vue(), tailwindcss(), viteSingleFile()],
  base: './',
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
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
  },
})
