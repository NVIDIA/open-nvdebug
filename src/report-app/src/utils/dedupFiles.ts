import type { FileRef } from '@/types/manifest'

export function dedupFiles(files: FileRef[]): FileRef[] {
  const seen = new Set<string>()
  return files.filter(f => {
    if (seen.has(f.path)) return false
    seen.add(f.path)
    return true
  })
}
