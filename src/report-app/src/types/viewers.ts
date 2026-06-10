export type ViewerType = 'monaco' | 'log-viewer' | 'json-tree' | 'download' | 'hex' | 'redfish'

export interface ViewerProps {
  filePath: string
  fileSize: number
  fileType: string
  content?: string
}
