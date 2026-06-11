/**
 * Resolves CSS custom property values at runtime for contexts that cannot
 * use `var()` directly — e.g., Chart.js datasets and HTML canvas drawing.
 *
 * Usage:
 *   const colors = useThemeColors()
 *   chartDataset.backgroundColor = colors.accent
 */
export function useThemeColors() {
  const root = document.documentElement
  const get = (prop: string): string =>
    getComputedStyle(root).getPropertyValue(prop).trim()

  return {
    accent: get('--nv-accent'),
    accentHover: get('--nv-accent-hover'),
    accentMuted: get('--nv-accent-muted'),

    success: get('--nv-success'),
    successMuted: get('--nv-success-muted'),
    error: get('--nv-error'),
    errorMuted: get('--nv-error-muted'),
    warning: get('--nv-warning'),
    warningMuted: get('--nv-warning-muted'),
    info: get('--nv-info'),
    infoMuted: get('--nv-info-muted'),

    skipped: get('--nv-skipped'),
    skippedMuted: get('--nv-skipped-muted'),

    bgPrimary: get('--nv-bg-primary'),
    bgSecondary: get('--nv-bg-secondary'),
    bgTertiary: get('--nv-bg-tertiary'),
    bgElevated: get('--nv-bg-elevated'),
    bgHover: get('--nv-bg-hover'),

    textPrimary: get('--nv-text-primary'),
    textSecondary: get('--nv-text-secondary'),
    textTertiary: get('--nv-text-tertiary'),

    border: get('--nv-border'),
    borderStrong: get('--nv-border-strong'),

    serviceRedfish: get('--nv-service-redfish'),
    serviceSsh: get('--nv-service-ssh'),
    serviceIpmi: get('--nv-service-ipmi'),
    serviceHealthCheck: get('--nv-service-health-check'),
    serviceHost: get('--nv-service-host'),
    serviceBmc: get('--nv-service-bmc'),
    servicePreflight: get('--nv-service-preflight'),

    chartBlue: get('--nv-chart-blue'),
    chartBlueLight: get('--nv-chart-blue-light'),
    chartPurple: get('--nv-chart-purple'),
    chartPurpleLight: get('--nv-chart-purple-light'),
    chartSlate: get('--nv-chart-slate'),
    chartSlateLight: get('--nv-chart-slate-light'),
    chartRed: get('--nv-chart-red'),
    chartGray: get('--nv-chart-gray'),

    gridColor: get('--nv-border') + '30',

    chartFontSize: Math.round(parseFloat(getComputedStyle(root).fontSize) * 0.785),
    chartFontSizeSm: Math.round(parseFloat(getComputedStyle(root).fontSize) * 0.7),
  }
}

export type ThemeColors = ReturnType<typeof useThemeColors>

const SERVICE_COLOR_PROPS: Record<string, string> = {
  redfish: '--nv-service-redfish',
  ssh: '--nv-service-ssh',
  ipmi: '--nv-service-ipmi',
  health_check: '--nv-service-health-check',
  host: '--nv-service-host',
  bmc: '--nv-service-bmc',
  preflight: '--nv-service-preflight',
}

const SERVICE_COLOR_FALLBACKS: Record<string, string> = {
  redfish: '#dc6976',
  ssh: '#ffc107',
  ipmi: '#0dcaf0',
  health_check: '#6f42c1',
  host: '#28a745',
  bmc: '#fd7e14',
  preflight: '#20c997',
  unknown: '#8f8f8f',
}

function normalizeColorKey(value: string): string {
  return value.trim().toLowerCase().replace(/[\s-]+/g, '_')
}

/**
 * Resolves a SERVICE_COLORS-style var() reference into an actual hex value.
 * For use with Chart.js where we pass SERVICE_COLORS[service] but need resolved values.
 */
export function resolveServiceColor(service: string): string {
  const key = normalizeColorKey(service)
  const prop = SERVICE_COLOR_PROPS[key]
  if (!prop) return SERVICE_COLOR_FALLBACKS.unknown
  const resolved = getComputedStyle(document.documentElement).getPropertyValue(prop).trim()
  return resolved || SERVICE_COLOR_FALLBACKS[key] || SERVICE_COLOR_FALLBACKS.unknown
}

/**
 * Resolves a STATUS_COLORS-style var() reference into an actual hex value.
 */
export function resolveStatusColor(status: string): string {
  const map: Record<string, string> = {
    success: '--nv-success',
    complete: '--nv-success',
    error: '--nv-error',
    partial: '--nv-warning',
    skipped: '--nv-skipped',
    not_ran: '--nv-text-tertiary',
    unknown: '--nv-text-tertiary',
  }
  const prop = map[status]
  if (!prop) return useThemeColors().chartGray
  return getComputedStyle(document.documentElement).getPropertyValue(prop).trim()
}
