import { defineStore } from 'pinia'
import type { FileEntry } from '@/types/manifest'

export const useFileSystemStore = defineStore('fileSystem', {
  state: () => ({
    mode: (typeof location !== 'undefined' && location.protocol === 'file:' ? 'file' : 'http') as 'file' | 'http',
    fileMap: new Map<string, File>(),
    directoryLoaded: false,
    integrityStatus: null as {
      total: number
      found: number
      missing: string[]
    } | null,
  }),

  getters: {
    needsDirectoryPicker: (state): boolean => state.mode === 'file' && !state.directoryLoaded,
    integrityOk: (state): boolean => state.integrityStatus !== null && state.integrityStatus.missing.length === 0,
  },

  actions: {
    loadDirectory(fileList: FileList) {
      this.fileMap.clear()
      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i]
        const relativePath = (file as any).webkitRelativePath as string
        if (relativePath) {
          const parts = relativePath.split('/')
          const pathWithoutRoot = parts.slice(1).join('/')
          if (pathWithoutRoot) {
            this.fileMap.set(pathWithoutRoot, file)
          }
        }
      }
      this.directoryLoaded = true
    },

    /**
     * Load files from a drag-drop. Accepts the DataTransferItemList from the
     * drop event. Walks any dropped directory entries recursively, stripping
     * the top-level directory so file paths match manifest entries.
     */
    async loadDirectoryFromDataTransfer(items: DataTransferItemList): Promise<void> {
      const entries: FileSystemEntry[] = []
      for (let i = 0; i < items.length; i++) {
        const entry = (items[i] as any).webkitGetAsEntry?.() as FileSystemEntry | null
        if (entry) entries.push(entry)
      }
      if (entries.length === 0) {
        throw new Error('Nothing droppable. Try dragging the folder itself, not its contents.')
      }
      const dirEntries = entries.filter((e) => e.isDirectory)
      if (dirEntries.length === 0) {
        throw new Error('Please drop a folder, not individual files.')
      }

      this.fileMap.clear()
      for (const dirEntry of dirEntries) {
        await collectFiles(dirEntry, this.fileMap)
      }
      this.directoryLoaded = true
    },

    checkIntegrity(fileIndex: FileEntry[]) {
      const missing: string[] = []
      for (const entry of fileIndex) {
        if (!this.fileMap.has(entry.path)) {
          missing.push(entry.path)
        }
      }
      this.integrityStatus = {
        total: fileIndex.length,
        found: fileIndex.length - missing.length,
        missing,
      }
    },

    /**
     * Quick post-selection sanity check. Returns true if at least one manifest
     * file was resolved in the picked/dropped directory. Callers use this to
     * reject wrong-folder picks with a helpful error rather than silently
     * accepting a useless selection.
     */
    validateAgainstManifest(fileIndex: FileEntry[]): { matched: number; total: number; sample: string[] } {
      let matched = 0
      for (const entry of fileIndex) {
        if (this.fileMap.has(entry.path)) matched++
      }
      const sample = fileIndex.slice(0, 3).map((e) => e.path)
      return { matched, total: fileIndex.length, sample }
    },

    getFile(path: string): File | undefined {
      return this.fileMap.get(path)
    },

    reset() {
      this.fileMap.clear()
      this.directoryLoaded = false
      this.integrityStatus = null
    },
  },
})

// Recursively walk a FileSystemDirectoryEntry and populate `map` with File
// objects keyed by their path relative to the dropped directory (the top-
// level directory name is stripped to match manifest entries).
async function collectFiles(root: FileSystemEntry, map: Map<string, File>): Promise<void> {
  const rootPrefix = root.fullPath.replace(/^\//, '') + '/'
  const stack: FileSystemEntry[] = [root]
  while (stack.length) {
    const entry = stack.pop()!
    if (entry.isFile) {
      const file = await new Promise<File>((resolve, reject) => {
        ;(entry as FileSystemFileEntry).file(resolve, reject)
      })
      // entry.fullPath starts with '/<root>/...'; strip the leading slash and
      // the root directory segment to match how webkitRelativePath is stripped.
      const rel = entry.fullPath.replace(/^\//, '')
      const relWithoutRoot = rel.startsWith(rootPrefix) ? rel.slice(rootPrefix.length) : rel
      if (relWithoutRoot) map.set(relWithoutRoot, file)
    } else if (entry.isDirectory) {
      const reader = (entry as FileSystemDirectoryEntry).createReader()
      // readEntries() only returns a batch; loop until empty.
      while (true) {
        const batch = await new Promise<FileSystemEntry[]>((resolve, reject) => {
          reader.readEntries(resolve, reject)
        })
        if (batch.length === 0) break
        stack.push(...batch)
      }
    }
  }
}
