/**
 * Normalize any CSS color to a 6-digit hex string (#RRGGBB).
 * Handles shorthand (#fff), 6-digit (#ffffff), rgb(), rgba(), and empty strings.
 * Returns fallback if parsing fails.
 */
export function toHex6(color: string, fallback = '#888888'): string {
  const c = color.trim()
  if (!c) return fallback

  if (c.startsWith('#')) {
    const hex = c.slice(1)
    if (hex.length === 3) {
      return '#' + hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2]
    }
    if (hex.length >= 6) {
      return '#' + hex.slice(0, 6)
    }
    return fallback
  }

  const rgbMatch = c.match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/)
  if (rgbMatch) {
    const r = parseInt(rgbMatch[1]).toString(16).padStart(2, '0')
    const g = parseInt(rgbMatch[2]).toString(16).padStart(2, '0')
    const b = parseInt(rgbMatch[3]).toString(16).padStart(2, '0')
    return `#${r}${g}${b}`
  }

  return fallback
}
