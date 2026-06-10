<template>
  <div ref="containerRef" class="nv-log" :style="{ height: height }"></div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, computed } from 'vue'
import * as monaco from 'monaco-editor'
import { useThemeStore } from '@/stores/theme'
import { useThemeColors } from '@/composables/useThemeColors'
import { toHex6 } from '@/utils/color'

const props = withDefaults(defineProps<{
  content: string
  language?: string
  height?: string
  fileName?: string
  readOnly?: boolean
  disableMinimap?: boolean
  wordWrap?: boolean
}>(), {
  language: 'plaintext',
  height: '500px',
  readOnly: true,
  disableMinimap: false,
  wordWrap: true,
})

const containerRef = ref<HTMLElement>()
const themeStore = useThemeStore()
let editor: monaco.editor.IStandaloneCodeEditor | null = null

const monacoThemeName = computed(() => themeStore.theme === 'dark' ? 'nv-dark' : 'nv-light')

const detectedLanguage = computed(() => {
  if (props.language !== 'plaintext') return props.language
  if (!props.fileName) return 'plaintext'

  const ext = props.fileName.split('.').pop()?.toLowerCase()
  const langMap: Record<string, string> = {
    json: 'json',
    js: 'javascript',
    ts: 'typescript',
    py: 'python',
    sh: 'shell',
    bash: 'shell',
    xml: 'xml',
    html: 'html',
    css: 'css',
    yaml: 'yaml',
    yml: 'yaml',
    md: 'markdown',
    log: 'plaintext',
    txt: 'plaintext',
    conf: 'ini',
    cfg: 'ini',
    ini: 'ini',
  }
  return langMap[ext ?? ''] ?? 'plaintext'
})

function defineNvThemes() {
  const colors = useThemeColors()
  const accent = toHex6(colors.accent, '#76B900')

  monaco.editor.defineTheme('nv-light', {
    base: 'vs',
    inherit: true,
    rules: [],
    colors: {
      'editor.background': '#FFFFFF',
      'editor.foreground': toHex6(colors.textPrimary, '#1A1A1A'),
      'editorLineNumber.foreground': toHex6(colors.textTertiary, '#616161'),
      'editor.selectionBackground': accent + '33',
    },
  })

  monaco.editor.defineTheme('nv-dark', {
    base: 'vs-dark',
    inherit: true,
    rules: [],
    colors: {
      'editor.background': toHex6(colors.bgElevated, '#2C2C2C'),
      'editor.foreground': toHex6(colors.textPrimary, '#E0E0E0'),
      'editorLineNumber.foreground': toHex6(colors.textSecondary, '#9E9E9E'),
      'editor.selectionBackground': accent + '33',
    },
  })
}

onMounted(() => {
  if (!containerRef.value) return

  defineNvThemes()

  editor = monaco.editor.create(containerRef.value, {
    value: props.content,
    language: detectedLanguage.value,
    theme: monacoThemeName.value,
    readOnly: props.readOnly,
    minimap: { enabled: !props.disableMinimap },
    scrollBeyondLastLine: false,
    wordWrap: props.wordWrap ? 'on' : 'off',
    fontSize: 13,
    lineNumbers: 'on',
    renderWhitespace: 'none',
    automaticLayout: true,
    folding: true,
    links: true,
    contextmenu: true,
    find: {
      addExtraSpaceOnTop: false,
      autoFindInSelection: 'never',
      seedSearchStringFromSelection: 'always',
    },
  })
})

watch(monacoThemeName, () => {
  if (!editor) return
  defineNvThemes()
  monaco.editor.setTheme(monacoThemeName.value)
})

watch(() => props.content, (newContent) => {
  if (editor && editor.getValue() !== newContent) {
    editor.setValue(newContent)
  }
})

watch(() => props.wordWrap, (wrap) => {
  if (editor) {
    editor.updateOptions({ wordWrap: wrap ? 'on' : 'off' })
  }
})

watch(detectedLanguage, (newLang) => {
  if (editor) {
    const model = editor.getModel()
    if (model) {
      monaco.editor.setModelLanguage(model, newLang)
    }
  }
})

onUnmounted(() => {
  if (editor) {
    editor.dispose()
    editor = null
  }
})
</script>
