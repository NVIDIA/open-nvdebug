import { ref } from 'vue'
import { showToast } from '@/composables/useToast'

const isExporting = ref(false)

export function usePdfExport() {
  async function exportToPdf(element: HTMLElement, filename = 'report.pdf') {
    if (isExporting.value) return
    isExporting.value = true
    showToast('Generating PDF...', 'info')

    try {
      const html2pdf = (await import('html2pdf.js')).default
      const opt = {
        margin: [10, 10, 10, 10] as [number, number, number, number],
        filename,
        image: { type: 'jpeg' as const, quality: 0.95 },
        html2canvas: {
          scale: 2,
          useCORS: true,
          logging: false,
          letterRendering: true,
          scrollX: 0,
          scrollY: 0,
        },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'landscape' as const },
        pagebreak: { mode: ['avoid-all', 'css', 'legacy'] },
      }

      await html2pdf().set(opt).from(element).save()
      showToast('PDF downloaded', 'success')
    } catch (err) {
      console.error('PDF export error:', err)
      showToast('PDF export failed', 'error')
    } finally {
      isExporting.value = false
    }
  }

  return { exportToPdf, isExporting }
}
