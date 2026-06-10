<template>
  <nav class="nv-navbar" role="navigation" aria-label="Main navigation">
    <button
      v-if="isMobile"
      class="nv-navbar__hamburger nv-btn nv-btn--ghost nv-btn--sm"
      aria-label="Toggle sidebar"
      @click="handleHamburgerClick"
    >
      <svg width="18" height="18" viewBox="0 0 18 18" fill="currentColor">
        <rect y="3" width="18" height="2" rx="1" />
        <rect y="8" width="18" height="2" rx="1" />
        <rect y="13" width="18" height="2" rx="1" />
      </svg>
    </button>

    <div class="nv-navbar__brand">
      <router-link to="/" style="display: flex; align-items: center; gap: 8px; text-decoration: none;">
        <svg class="nv-navbar__logo" width="26" height="20" viewBox="0 0 34 30" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M16.889 8.985V6.28c.262-.02.528-.033.798-.042 7.4-.232 12.255 6.359 12.255 6.359s-5.244 7.282-10.866 7.282a6.82 6.82 0 0 1-2.187-.35v-8.204c2.88.348 3.46 1.62 5.192 4.508l3.852-3.248s-2.812-3.688-7.552-3.688c-.515 0-1.008.036-1.492.088zm0-8.938V4.09c.265-.021.531-.038.798-.048 10.29-.346 16.995 8.44 16.995 8.44s-7.7 9.364-15.723 9.364c-.735 0-1.424-.068-2.07-.183v2.498c.553.07 1.126.112 1.724.112 7.465 0 12.864-3.812 18.092-8.325.867.694 4.416 2.383 5.145 3.123-4.971 4.16-16.555 7.515-23.123 7.515a18.89 18.89 0 0 1-1.838-.096V30h28.375V.047H16.89zm0 19.482v2.133c-6.905-1.23-8.822-8.408-8.822-8.408s3.316-3.674 8.822-4.269v2.34l-.011-.001c-2.89-.347-5.147 2.353-5.147 2.353s1.265 4.544 5.158 5.852zM4.625 12.943s4.092-6.04 12.264-6.663V4.088C7.838 4.815 0 12.48 0 12.48s4.439 12.833 16.889 14.008V24.16C7.753 23.011 4.625 12.943 4.625 12.943z" fill="#76B900"/>
        </svg>
        <span class="nv-navbar__brand-name">NVIDIA</span>
        <span v-if="!isMobile" class="nv-navbar__brand-label">NVDebug Reports</span>
      </router-link>
    </div>

    <div v-if="!isMobile" class="nv-navbar__nav" role="menubar" aria-label="Page navigation">
      <router-link to="/" class="navbar-link" active-class="navbar-link--active" :class="{ 'navbar-link--active': $route.path === '/' }">
        Dashboard
      </router-link>
      <router-link to="/timing" class="navbar-link" active-class="navbar-link--active">
        Timing
      </router-link>
      <router-link to="/file-map" class="navbar-link" active-class="navbar-link--active">
        Files
      </router-link>

      <div class="navbar-dropdown" ref="analysisDropdownRef">
        <button class="navbar-link navbar-dropdown__trigger" :class="{ 'navbar-link--active': isAnalysisRoute }" @click="showAnalysis = !showAnalysis">
          Analysis
          <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor" style="opacity: 0.6;" :style="{ transform: showAnalysis ? 'rotate(180deg)' : '' }"><path d="M2 4l3 3 3-3"/></svg>
        </button>
        <div v-show="showAnalysis" class="navbar-dropdown__menu nv-glass--elevated" style="max-height: calc(100vh - 100px); overflow-y: auto; min-width: 240px;">
          <span class="navbar-dropdown__section">Insights</span>
          <router-link to="/anomalies" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9888;</span>
            Anomalies
          </router-link>
          <router-link to="/co-failure" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9736;</span>
            Co-Failure Analysis
          </router-link>
          <router-link to="/error-timeline" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#8986;</span>
            Error Timeline
          </router-link>
          <router-link to="/errors" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#10060;</span>
            Error Aggregation
          </router-link>

          <span class="navbar-dropdown__section">Coverage</span>
          <router-link to="/service-health" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9829;</span>
            Service Health
          </router-link>
          <router-link to="/coverage" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9638;</span>
            Coverage Matrix
          </router-link>
          <router-link to="/efficiency" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9733;</span>
            Collection Efficiency
          </router-link>
          <router-link to="/stage-profiling" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9201;</span>
            Stage Profiling
          </router-link>

          <span class="navbar-dropdown__section">Comparison</span>
          <router-link to="/compare" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#8596;</span>
            DUT Comparison
          </router-link>
          <router-link to="/firmware-compare" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9881;</span>
            Firmware Comparison
          </router-link>
          <router-link to="/compare-runs" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#128200;</span>
            Run Comparison
          </router-link>

          <span class="navbar-dropdown__section">Infrastructure</span>
          <router-link to="/preflight-summary" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9989;</span>
            Preflight Summary
          </router-link>
          <router-link to="/dependencies" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9679;</span>
            Dependency Graph
          </router-link>
          <router-link to="/heatmap" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9632;</span>
            Health Heatmap
          </router-link>

          <span class="navbar-dropdown__section">Tools</span>
          <router-link to="/correlate" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#8644;</span>
            Log Correlation
          </router-link>
          <router-link to="/diff" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#177;</span>
            File Diff
          </router-link>
          <router-link to="/timing/gantt" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9776;</span>
            Execution Timeline
          </router-link>
          <router-link to="/split" class="navbar-dropdown__item" @click="showAnalysis = false">
            <span class="navbar-dropdown__icon">&#9114;</span>
            Split File View
          </router-link>
        </div>
      </div>
    </div>

    <div class="nv-navbar__search">
      <input
        type="text"
        v-model="searchQuery"
        placeholder="Search... (Ctrl+K)"
        @focus="$emit('open-search')"
        readonly
        class="nv-input nv-input--sm"
      />
    </div>

    <div class="nv-navbar__actions">
      <!-- Theme toggle -->
      <button @click="themeStore.toggle()" class="nv-btn nv-btn--ghost nv-btn--sm" :title="themeStore.theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'">
        <svg v-if="themeStore.theme === 'dark'" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="5"/>
          <line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
          <line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
        </svg>
        <svg v-else width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
        </svg>
      </button>
      <!-- Print -->
      <button v-if="!isMobile" class="nv-btn nv-btn--ghost nv-btn--sm no-print" title="Print / Export PDF" @click="handlePrint">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/>
          <rect x="6" y="14" width="12" height="8"/>
        </svg>
      </button>
      <!-- Font size -->
      <button v-if="!isMobile" class="nv-btn nv-btn--ghost nv-btn--sm navbar-action-label" @click="themeStore.cycleFontSize()" :title="`Font size: ${themeStore.fontSize.toUpperCase()}`">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/>
        </svg>
        <span class="navbar-action-label__text">{{ themeStore.fontSize.toUpperCase() }}</span>
      </button>
      <!-- Export -->
      <button v-if="!isMobile" @click="handleExport" class="nv-btn nv-btn--ghost nv-btn--sm navbar-action-label" title="Export manifest JSON">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
        <span class="navbar-action-label__text">Export</span>
      </button>
      <!-- Shortcuts -->
      <button v-if="!isMobile" @click="$emit('show-shortcuts')" class="nv-btn nv-btn--ghost nv-btn--sm" title="Keyboard shortcuts (?)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="2" y="4" width="20" height="16" rx="2"/><path d="M6 8h.01M10 8h.01M14 8h.01M18 8h.01M8 12h.01M12 12h.01M16 12h.01M7 16h10"/>
        </svg>
      </button>
    </div>

    <!-- Mobile nav dropdown -->
    <Transition name="mobile-menu">
      <div v-if="isMobile && mobileMenuOpen" class="nv-navbar__mobile-menu nv-glass--elevated" ref="mobileMenuRef">
        <router-link to="/" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">
          Dashboard
        </router-link>
        <router-link to="/timing" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">
          Timing
        </router-link>
        <router-link to="/file-map" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">
          Files
        </router-link>
        <div class="nv-navbar__mobile-divider"></div>
        <span class="nv-navbar__mobile-section">Insights</span>
        <router-link to="/anomalies" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Anomalies</router-link>
        <router-link to="/co-failure" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Co-Failure Analysis</router-link>
        <router-link to="/error-timeline" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Error Timeline</router-link>
        <router-link to="/errors" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Error Aggregation</router-link>
        <span class="nv-navbar__mobile-section">Coverage</span>
        <router-link to="/service-health" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Service Health</router-link>
        <router-link to="/coverage" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Coverage Matrix</router-link>
        <router-link to="/efficiency" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Collection Efficiency</router-link>
        <router-link to="/stage-profiling" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Stage Profiling</router-link>
        <span class="nv-navbar__mobile-section">Comparison</span>
        <router-link to="/compare" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">DUT Comparison</router-link>
        <router-link to="/firmware-compare" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Firmware Comparison</router-link>
        <router-link to="/compare-runs" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Run Comparison</router-link>
        <span class="nv-navbar__mobile-section">Infrastructure</span>
        <router-link to="/preflight-summary" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Preflight Summary</router-link>
        <router-link to="/dependencies" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Dependency Graph</router-link>
        <router-link to="/heatmap" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Health Heatmap</router-link>
        <span class="nv-navbar__mobile-section">Tools</span>
        <router-link to="/correlate" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Log Correlation</router-link>
        <router-link to="/diff" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">File Diff</router-link>
        <router-link to="/timing/gantt" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Execution Timeline</router-link>
        <router-link to="/split" class="nv-navbar__mobile-link" @click="mobileMenuOpen = false">Split File View</router-link>
        <div class="nv-navbar__mobile-divider"></div>
        <button class="nv-navbar__mobile-link" @click="handleExport(); mobileMenuOpen = false">
          Export
        </button>
        <button class="nv-navbar__mobile-link" @click="$emit('show-shortcuts'); mobileMenuOpen = false">
          Keyboard Shortcuts
        </button>
      </div>
    </Transition>
  </nav>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { useThemeStore } from '@/stores/theme'
import { useManifestStore } from '@/stores/manifest'
import { exportManifest } from '@/services/exportService'

const emit = defineEmits<{
  'toggle-sidebar': []
  'open-search': []
  'show-shortcuts': []
}>()

const route = useRoute()
const themeStore = useThemeStore()
const manifestStore = useManifestStore()
const showAnalysis = ref(false)
const mobileMenuOpen = ref(false)
const analysisDropdownRef = ref<HTMLElement>()
const mobileMenuRef = ref<HTMLElement>()

const ANALYSIS_PATHS = ['/anomalies', '/co-failure', '/error-timeline', '/errors', '/service-health', '/coverage', '/efficiency', '/stage-profiling', '/compare', '/firmware-compare', '/compare-runs', '/preflight-summary', '/dependencies', '/heatmap', '/correlate', '/diff', '/timing/gantt', '/split']
const isAnalysisRoute = computed(() => ANALYSIS_PATHS.some(p => route.path.startsWith(p)))

function onClickOutside(e: MouseEvent) {
  if (showAnalysis.value && analysisDropdownRef.value && !analysisDropdownRef.value.contains(e.target as Node)) {
    showAnalysis.value = false
  }
  if (mobileMenuOpen.value && mobileMenuRef.value && !mobileMenuRef.value.contains(e.target as Node)) {
    const hamburger = (e.target as HTMLElement).closest('.nv-navbar__hamburger')
    if (!hamburger) mobileMenuOpen.value = false
  }
}

function handleHamburgerClick() {
  mobileMenuOpen.value = !mobileMenuOpen.value
  emit('toggle-sidebar')
}

function handleExport() {
  if (manifestStore.manifest) exportManifest(manifestStore.manifest)
}

function handlePrint() {
  window.print()
}
const searchQuery = ref('')
const windowWidth = ref(window.innerWidth)

const isMobile = computed(() => windowWidth.value < 1024)

function onResize() {
  windowWidth.value = window.innerWidth
  if (!isMobile.value) mobileMenuOpen.value = false
}

onMounted(() => {
  window.addEventListener('resize', onResize)
  document.addEventListener('click', onClickOutside)
})
onUnmounted(() => {
  window.removeEventListener('resize', onResize)
  document.removeEventListener('click', onClickOutside)
})
</script>

<style scoped>
.nv-navbar__nav {
  display: flex;
  align-items: center;
  gap: 2px;
  margin-left: 16px;
}

.navbar-link {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 6px 12px;
  font-size: var(--nv-text-sm);
  font-weight: var(--nv-weight-medium);
  color: var(--nv-text-secondary);
  text-decoration: none;
  border-radius: var(--nv-radius-md);
  border: none;
  background: none;
  cursor: pointer;
  transition: all var(--nv-duration-fast) var(--nv-ease);
  white-space: nowrap;
  font-family: var(--nv-font-family);
}
.navbar-link:hover {
  color: var(--nv-text-primary);
  background: var(--nv-glass-bg-light);
}
.navbar-link--active {
  color: var(--nv-accent);
  background: var(--nv-accent-subtle);
}

.navbar-dropdown {
  position: relative;
}
.navbar-dropdown__trigger {
  line-height: 1;
}
.navbar-dropdown__menu {
  position: absolute;
  top: calc(100% + 4px);
  left: 0;
  min-width: 220px;
  padding: 6px;
  border-radius: var(--nv-radius-lg);
  z-index: var(--nv-z-dropdown);
  display: flex;
  flex-direction: column;
  gap: 1px;
}
.navbar-dropdown__item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  font-size: var(--nv-text-sm);
  color: var(--nv-text-secondary);
  text-decoration: none;
  border-radius: var(--nv-radius-md);
  transition: all var(--nv-duration-fast) var(--nv-ease);
}
.navbar-dropdown__item:hover {
  color: var(--nv-text-primary);
  background: var(--nv-glass-bg-light);
}
.navbar-dropdown__icon {
  width: 18px;
  text-align: center;
  font-size: 0.875rem;
  flex-shrink: 0;
}
.navbar-dropdown__section {
  display: block;
  font-size: 0.5625rem;
  font-weight: 700;
  color: var(--nv-text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 8px 12px 3px;
  margin-top: 2px;
}
.navbar-dropdown__section:first-child {
  margin-top: 0;
  padding-top: 4px;
}

/* ── Hamburger ── */
.nv-navbar__hamburger {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 6px;
}

/* ── Mobile Menu ── */
.nv-navbar__mobile-menu {
  position: absolute;
  top: 52px;
  left: 0;
  right: 0;
  max-height: calc(100vh - 52px);
  overflow-y: auto;
  padding: var(--nv-space-2);
  display: flex;
  flex-direction: column;
  z-index: var(--nv-z-dropdown);
  border-top: 1px solid var(--nv-glass-border);
  border-radius: 0 0 var(--nv-radius-lg) var(--nv-radius-lg);
}
.nv-navbar__mobile-link {
  display: flex;
  align-items: center;
  gap: var(--nv-space-2);
  padding: var(--nv-space-2) var(--nv-space-3);
  font-size: var(--nv-text-sm);
  font-weight: var(--nv-weight-medium);
  color: var(--nv-text-secondary);
  text-decoration: none;
  border-radius: var(--nv-radius-md);
  border: none;
  background: none;
  cursor: pointer;
  transition: all var(--nv-duration-fast) var(--nv-ease);
  font-family: var(--nv-font-family);
  width: 100%;
  text-align: left;
  min-height: 44px;
}
.nv-navbar__mobile-link:hover {
  color: var(--nv-text-primary);
  background: var(--nv-glass-bg-light);
}
.nv-navbar__mobile-link.router-link-active {
  color: var(--nv-accent);
  background: var(--nv-accent-subtle);
}
.nv-navbar__mobile-divider {
  height: 1px;
  background: var(--nv-glass-border);
  margin: var(--nv-space-1) var(--nv-space-3);
}
.nv-navbar__mobile-section {
  font-size: var(--nv-text-xs);
  font-weight: var(--nv-weight-semibold);
  color: var(--nv-text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: var(--nv-space-2) var(--nv-space-3) var(--nv-space-1);
}

/* ── Mobile menu transition ── */
.mobile-menu-enter-active,
.mobile-menu-leave-active {
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.mobile-menu-enter-from,
.mobile-menu-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}

/* ── Navbar action buttons with icon + label ── */
.navbar-action-label {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.navbar-action-label__text {
  font-size: 0.6875rem;
  font-weight: 600;
  letter-spacing: 0.02em;
}
</style>
