<template>
  <Transition name="app-enter">
    <div v-if="appReady" id="app" :data-theme="themeStore.theme" style="min-height: 100vh; display: flex; flex-direction: column;">
      <AppNavbar
        @open-search="commandPaletteRef?.show()"
        @show-shortcuts="shortcutHelpRef?.show()"
      />

      <div
        v-if="fileSystemStore.integrityStatus && !fileSystemStore.integrityOk"
        class="nv-banner nv-banner--warning"
        style="margin-top: 52px; margin-bottom: 0;"
      >
        <span>&#9888;&#65039;</span>
        <span>
          {{ fileSystemStore.integrityStatus.missing.length }} of {{ fileSystemStore.integrityStatus.total }} files not found — partial archive?
        </span>
      </div>

      <main class="nv-app-main">
        <DirectoryPicker />
        <router-view v-slot="{ Component }">
          <Transition name="page" mode="out-in">
            <component :is="Component" :key="$route.path" />
          </Transition>
        </router-view>
      </main>

      <footer class="nv-app-footer no-print">
        <span>NVDebug v{{ manifestStore.toolVersion }}</span>
        <span class="nv-app-footer__sep">|</span>
        <span>Generated {{ manifestStore.generatedAt }}</span>
        <span class="nv-app-footer__sep">|</span>
        <span>{{ manifestStore.manifest?.duts.length ?? 0 }} DUTs</span>
      </footer>

      <CrossFileGrepPanel />
      <CommandPalette ref="commandPaletteRef" />
      <QuickFileOpen ref="quickFileOpenRef" />
      <ShortcutHelpModal ref="shortcutHelpRef" />
      <OnboardingTour ref="onboardingRef" />
      <NavigationProgress />
      <Toast />
      <BackToTop />
    </div>
  </Transition>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import AppNavbar from '@/components/layout/AppNavbar.vue'
import DirectoryPicker from '@/components/layout/DirectoryPicker.vue'
import CrossFileGrepPanel from '@/components/layout/CrossFileGrepPanel.vue'
import CommandPalette from '@/components/common/CommandPalette.vue'
import QuickFileOpen from '@/components/common/QuickFileOpen.vue'
import ShortcutHelpModal from '@/components/common/ShortcutHelpModal.vue'
import OnboardingTour from '@/components/common/OnboardingTour.vue'
import NavigationProgress from '@/components/layout/NavigationProgress.vue'
import Toast from '@/components/common/Toast.vue'
import BackToTop from '@/components/common/BackToTop.vue'
import { useThemeStore } from '@/stores/theme'
import { useManifestStore } from '@/stores/manifest'
import { useFileSystemStore } from '@/stores/fileSystem'
import { useSearchStore } from '@/stores/search'
import { useAnnotationsStore } from '@/stores/annotations'

const vueRouter = useRouter()
const vueRoute = useRoute()
const themeStore = useThemeStore()
const manifestStore = useManifestStore()
const fileSystemStore = useFileSystemStore()
const searchStore = useSearchStore()
const annotationsStore = useAnnotationsStore()

const appReady = ref(false)
const commandPaletteRef = ref<InstanceType<typeof CommandPalette>>()
const quickFileOpenRef = ref<InstanceType<typeof QuickFileOpen>>()
const shortcutHelpRef = ref<InstanceType<typeof ShortcutHelpModal>>()
const onboardingRef = ref<InstanceType<typeof OnboardingTour>>()

function onGlobalKeydown(e: KeyboardEvent) {
  const target = e.target as HTMLElement
  if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
    if (e.key !== 'Escape') return
  }

  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault()
    commandPaletteRef.value?.show()
    return
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 'p') {
    e.preventDefault()
    quickFileOpenRef.value?.show()
    return
  }
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'F') {
    e.preventDefault()
    searchStore.grepPanelOpen = true
    return
  }
  if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
    shortcutHelpRef.value?.show()
    return
  }
  if (e.key === 't' && !e.ctrlKey && !e.metaKey) {
    themeStore.toggle()
    return
  }
  if (e.key === '\\' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault()
    if (vueRoute.name === 'split-file') {
      vueRouter.back()
    } else {
      const query: Record<string, string> = {}
      if (vueRoute.name === 'file' && vueRoute.params.encodedPath) {
        query.left = String(vueRoute.params.encodedPath)
      }
      vueRouter.push({ name: 'split-file', query })
    }
    return
  }
}

onMounted(() => {
  themeStore.init()
  manifestStore.loadFromWindow()
  if (manifestStore.generatedAt) {
    annotationsStore.init(manifestStore.generatedAt)
  }
  window.addEventListener('keydown', onGlobalKeydown)
  appReady.value = true
})

onUnmounted(() => {
  window.removeEventListener('keydown', onGlobalKeydown)
})
</script>

<style>
.nv-app-main {
  flex: 1;
  margin-top: 52px;
  padding-bottom: 36px;
  overflow-x: clip;
}

.app-enter-enter-active {
  transition: opacity 0.35s ease;
}
.app-enter-enter-from {
  opacity: 0;
}

.page-enter-active {
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.page-leave-active {
  transition: opacity 0.1s ease, transform 0.1s ease;
}
.page-enter-from {
  opacity: 0;
  transform: translateY(6px);
}
.page-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}
</style>
