/**
 * Format a duration in seconds to a human-readable string.
 * Scales to ms, seconds, minutes, hours as appropriate.
 *
 *   0       -> "0s"
 *   0.045   -> "45ms"
 *   1.5     -> "1.5s"
 *   65      -> "1m 5s"
 *   3725    -> "1h 2m 5s"
 */
export function formatDuration(seconds: number): string {
  if (seconds == null || isNaN(seconds)) return '\u2014'
  if (seconds === 0) return '0s'

  const abs = Math.abs(seconds)
  const sign = seconds < 0 ? '-' : ''

  if (abs < 1) {
    const ms = Math.round(abs * 1000)
    return ms === 0 ? '0s' : `${sign}${ms}ms`
  }

  if (abs < 60) {
    return `${sign}${abs.toFixed(1)}s`
  }

  const h = Math.floor(abs / 3600)
  const m = Math.floor((abs % 3600) / 60)
  const s = Math.round(abs % 60)

  if (h > 0) {
    return `${sign}${h}h ${m}m ${s}s`
  }
  return `${sign}${m}m ${s}s`
}

/**
 * Format bytes into a human-readable size string.
 */
export function formatBytes(b: number): string {
  if (b == null || isNaN(b) || b < 0) return '\u2014'
  if (b < 1024) return b + ' B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB'
  if (b < 1024 * 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + ' MB'
  return (b / (1024 * 1024 * 1024)).toFixed(1) + ' GB'
}
