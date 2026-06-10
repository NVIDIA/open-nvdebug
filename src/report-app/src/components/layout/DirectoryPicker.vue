<template>
  <div v-if="fileSystemStore.needsDirectoryPicker && showBanner" class="nv-dir-picker">
    <div class="nv-dir-picker__header">
      <div class="nv-dir-picker__title-block">
        <p class="nv-dir-picker__title">Enable file viewing</p>
        <p class="nv-dir-picker__subtitle">
          Browsers block <code>file://</code> pages from reading neighbor files without permission.
          Grant access once &mdash; files stay on your machine.
          <button type="button" class="nv-link" @click="expanded = !expanded">
            {{ expanded ? 'Hide details' : 'Details' }}
          </button>
        </p>
      </div>
      <div class="nv-dir-picker__actions">
        <label class="nv-btn nv-btn--primary">
          Select Folder
          <input
            type="file"
            webkitdirectory
            style="display: none;"
            @change="onDirectorySelected"
          />
        </label>
        <button
          type="button"
          class="nv-btn nv-btn--ghost"
          title="Dismiss (you can re-open from the file view)"
          @click="showBanner = false"
        >&times;</button>
      </div>
    </div>

    <div v-if="expanded" class="nv-dir-picker__details">
      <div
        class="nv-dir-picker__dropzone"
        :class="{ 'is-over': isDragOver }"
        @dragover.prevent="onDragOver"
        @dragleave.prevent="isDragOver = false"
        @drop.prevent="onDrop"
      >
        <p class="nv-dir-picker__dropzone-title">
          Drag the folder here
        </p>
        <p v-if="expected.name" class="nv-dir-picker__dropzone-path">
          Expected folder: <code>{{ expected.name }}</code>
          <button
            v-if="expected.fullPath"
            type="button"
            class="nv-link"
            @click="copyPath"
          >{{ copied ? 'Copied' : 'Copy full path' }}</button>
        </p>
        <p class="nv-dir-picker__dropzone-hint">
          Or use the <strong>Select Folder</strong> button above.
          Drag-drop has no "Upload N files?" confirmation.
        </p>
      </div>

      <p v-if="lastError" class="nv-dir-picker__error">
        {{ lastError }}
      </p>

      <details class="nv-dir-picker__explain">
        <summary>Why is this required?</summary>
        <p>
          You opened the report directly from disk (<code>file://</code>).
          For security, browsers treat every <code>file://</code> page as its own
          origin and block it from reading any other file without an explicit
          user gesture &mdash; even files in the same folder. Selecting or
          dropping the folder tells the browser it's OK to expose those files
          to this page. <strong>No upload happens.</strong> Bytes never leave
          your machine.
        </p>
      </details>

      <details class="nv-dir-picker__explain">
        <summary>Serving on a web server? No setup needed.</summary>
        <p>
          If you host the output directory on any HTTP server, this prompt
          disappears and file viewing works instantly. From the output folder:
        </p>
        <pre class="nv-dir-picker__code">python3 -m http.server 8000</pre>
        <p>
          Then open <code>http://localhost:8000/reports/</code>. No folder picker,
          no drop zone, no permission dialogs.
        </p>
      </details>

      <details class="nv-dir-picker__explain">
        <summary>What if I dismiss this?</summary>
        <ul class="nv-dir-picker__list">
          <li>The dashboard, timing view, and summary tables still work &mdash; report data is already embedded.</li>
          <li>Individual log file views will show this prompt instead of log contents.</li>
          <li>Cross-file search, diff, and split-view all need access to work.</li>
          <li>The original log files on disk are untouched &mdash; you can open them in any external editor.</li>
        </ul>
      </details>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useFileSystemStore } from '@/stores/fileSystem'
import { useManifestStore } from '@/stores/manifest'

const fileSystemStore = useFileSystemStore()
const manifestStore = useManifestStore()

const showBanner = ref(true)
const expanded = ref(false)
const isDragOver = ref(false)
const copied = ref(false)
const lastError = ref<string | null>(null)

// Derive the expected parent folder from the page URL. When the user opens
// `<collection>/reports/index.html`, the folder they must select is
// `<collection>/`. We can only *display* this path — the browser refuses to
// pre-seed the picker with it, so the user still has to click/drop.
const expected = computed<{ name: string; fullPath: string }>(() => {
  try {
    if (typeof location === 'undefined') return { name: '', fullPath: '' }
    const pathname = decodeURIComponent(location.pathname)
    const parts = pathname.split('/').filter(Boolean)
    // Typical layout: /.../<collection>/reports/index.html → drop 'reports' +
    // 'index.html' to reach <collection>.
    let targetParts: string[]
    if (parts.length >= 2 && parts[parts.length - 2] === 'reports') {
      targetParts = parts.slice(0, -2)
    } else {
      targetParts = parts.slice(0, -1)
    }
    if (targetParts.length === 0) return { name: '', fullPath: '' }
    return {
      name: targetParts[targetParts.length - 1],
      fullPath: '/' + targetParts.join('/'),
    }
  } catch {
    return { name: '', fullPath: '' }
  }
})

function onDragOver(e: DragEvent) {
  if (e.dataTransfer) e.dataTransfer.dropEffect = 'link'
  isDragOver.value = true
}

async function onDrop(e: DragEvent) {
  isDragOver.value = false
  lastError.value = null
  if (!e.dataTransfer?.items?.length) {
    lastError.value = 'No folder detected in the drop.'
    return
  }
  try {
    await fileSystemStore.loadDirectoryFromDataTransfer(e.dataTransfer.items)
    afterLoad()
  } catch (err) {
    lastError.value = err instanceof Error ? err.message : String(err)
  }
}

function onDirectorySelected(event: Event) {
  lastError.value = null
  const input = event.target as HTMLInputElement
  if (input.files && input.files.length > 0) {
    fileSystemStore.loadDirectory(input.files)
    afterLoad()
  }
}

function afterLoad() {
  if (!manifestStore.loaded) return
  const { matched, total, sample } = fileSystemStore.validateAgainstManifest(manifestStore.fileIndex)
  if (matched === 0 && total > 0) {
    // Wrong folder — reset and explain rather than silently accepting.
    fileSystemStore.reset()
    const hint = expected.value.name
      ? `Expected folder: ${expected.value.name}/ (contains reports/ and your DUT folders).`
      : `Expected folder should contain reports/ and your DUT folders.`
    const example = sample.length ? ` Example missing path: ${sample[0]}` : ''
    lastError.value = `That folder doesn't contain the expected files. ${hint}${example}`
    return
  }
  fileSystemStore.checkIntegrity(manifestStore.fileIndex)
}

async function copyPath() {
  if (!expected.value.fullPath) return
  try {
    await navigator.clipboard.writeText(expected.value.fullPath)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  } catch {
    copied.value = false
  }
}
</script>

<style scoped>
.nv-dir-picker {
  display: flex;
  flex-direction: column;
  gap: var(--nv-space-3);
  padding: var(--nv-space-3) var(--nv-space-4);
  margin: var(--nv-space-4);
  background: var(--nv-glass-bg);
  backdrop-filter: var(--nv-glass-blur);
  -webkit-backdrop-filter: var(--nv-glass-blur);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-lg);
}
.nv-dir-picker__header {
  display: flex;
  align-items: center;
  gap: var(--nv-space-4);
}
.nv-dir-picker__title-block {
  flex: 1;
  min-width: 0;
}
.nv-dir-picker__title {
  margin: 0 0 4px 0;
  font-weight: 600;
  color: var(--nv-text-primary);
}
.nv-dir-picker__subtitle {
  margin: 0;
  font-size: 0.8125rem;
  color: var(--nv-text-secondary);
}
.nv-dir-picker__subtitle code {
  font-size: 0.75rem;
}
.nv-dir-picker__actions {
  display: flex;
  gap: var(--nv-space-2);
  flex-shrink: 0;
}
.nv-dir-picker__details {
  display: flex;
  flex-direction: column;
  gap: var(--nv-space-3);
  padding-top: var(--nv-space-2);
  border-top: 1px solid var(--nv-glass-border);
}
.nv-dir-picker__dropzone {
  border: 2px dashed var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
  padding: var(--nv-space-4);
  text-align: center;
  transition: border-color 0.15s ease, background-color 0.15s ease;
  background: color-mix(in srgb, var(--nv-glass-bg) 60%, transparent);
}
.nv-dir-picker__dropzone.is-over {
  border-color: var(--nv-success, #76b900);
  background: color-mix(in srgb, var(--nv-success, #76b900) 10%, transparent);
}
.nv-dir-picker__dropzone-title {
  margin: 0 0 6px 0;
  font-weight: 600;
  color: var(--nv-text-primary);
}
.nv-dir-picker__dropzone-path {
  margin: 0 0 6px 0;
  font-size: 0.8125rem;
  color: var(--nv-text-secondary);
}
.nv-dir-picker__dropzone-path code {
  font-size: 0.8125rem;
  padding: 2px 6px;
  background: var(--nv-glass-bg);
  border-radius: var(--nv-radius-sm, 4px);
}
.nv-dir-picker__dropzone-hint {
  margin: 0;
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
  opacity: 0.8;
}
.nv-dir-picker__error {
  margin: 0;
  padding: var(--nv-space-2) var(--nv-space-3);
  font-size: 0.8125rem;
  color: var(--nv-error);
  background: color-mix(in srgb, var(--nv-error) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--nv-error) 30%, transparent);
  border-radius: var(--nv-radius-md);
}
.nv-dir-picker__explain {
  font-size: 0.8125rem;
  color: var(--nv-text-secondary);
}
.nv-dir-picker__explain summary {
  cursor: pointer;
  font-weight: 600;
  color: var(--nv-text-primary);
  padding: 4px 0;
}
.nv-dir-picker__explain p,
.nv-dir-picker__explain ul {
  margin: 6px 0;
}
.nv-dir-picker__list {
  padding-left: 20px;
}
.nv-dir-picker__list li {
  margin: 3px 0;
}
.nv-dir-picker__code {
  margin: 6px 0;
  padding: 8px 10px;
  background: var(--nv-glass-bg);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-sm, 4px);
  font-size: 0.75rem;
  overflow-x: auto;
}
.nv-link {
  background: none;
  border: none;
  padding: 0;
  margin-left: 8px;
  color: var(--nv-accent, #76b900);
  font-size: inherit;
  cursor: pointer;
  text-decoration: underline;
}
.nv-link:hover {
  opacity: 0.8;
}
</style>
