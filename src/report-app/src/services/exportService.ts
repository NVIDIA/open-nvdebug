/**
 * Client-side export utilities — generates Blobs for download.
 */

export function exportCsv(columns: string[], rows: Record<string, any>[]): void {
  const header = columns.join(',')
  const body = rows.map(row =>
    columns.map(col => {
      const val = String(row[col] ?? '')
      return val.includes(',') || val.includes('"') || val.includes('\n')
        ? `"${val.replace(/"/g, '""')}"`
        : val
    }).join(',')
  ).join('\n')
  downloadBlob(`${header}\n${body}`, 'export.csv', 'text/csv')
}

export function exportJson(data: any, filename = 'export.json'): void {
  downloadBlob(JSON.stringify(data, null, 2), filename, 'application/json')
}

export function exportText(text: string, filename = 'export.txt'): void {
  downloadBlob(text, filename, 'text/plain')
}

export function exportManifest(manifest: any): void {
  exportJson(manifest, 'manifest.json')
}

function downloadBlob(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
