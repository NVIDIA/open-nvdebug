export const STATUS_COLORS: Record<string, string> = {
  success: 'var(--nv-success)',
  error: 'var(--nv-error)',
  partial: 'var(--nv-warning)',
  skipped: 'var(--nv-skipped)',
  not_ran: 'var(--nv-text-tertiary)',
  unknown: 'var(--nv-text-tertiary)',
  complete: 'var(--nv-success)',
}

export const STATUS_BG_COLORS: Record<string, string> = {
  success: 'var(--nv-success-muted)',
  error: 'var(--nv-error-muted)',
  partial: 'var(--nv-warning-muted)',
  skipped: 'var(--nv-skipped-muted)',
  not_ran: 'var(--nv-bg-tertiary)',
  unknown: 'var(--nv-bg-tertiary)',
  complete: 'var(--nv-success-muted)',
}

export const SERVICE_COLORS: Record<string, string> = {
  redfish: 'var(--nv-service-redfish)',
  ssh: 'var(--nv-service-ssh)',
  ipmi: 'var(--nv-service-ipmi)',
  health_check: 'var(--nv-service-health-check)',
  host: 'var(--nv-service-host)',
  bmc: 'var(--nv-service-bmc)',
  preflight: 'var(--nv-service-preflight)',
}
