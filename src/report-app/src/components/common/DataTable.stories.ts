import type { Meta, StoryObj } from '@storybook/vue3'
import DataTable from './DataTable.vue'

const meta: Meta<typeof DataTable> = {
  title: 'Common/DataTable',
  component: DataTable,
  tags: ['autodocs'],
}
export default meta

type Story = StoryObj<typeof DataTable>

const sampleColumns = [
  { key: 'name', label: 'Name', sortable: true },
  { key: 'status', label: 'Status', sortable: true },
  { key: 'duration', label: 'Duration (s)', sortable: true },
  { key: 'size', label: 'Size', sortable: true },
]

const sampleData = Array.from({ length: 30 }, (_, i) => ({
  name: `Collector_${String(i + 1).padStart(3, '0')}`,
  status: ['success', 'error', 'partial', 'skipped'][i % 4],
  duration: +(Math.random() * 120).toFixed(1),
  size: Math.floor(Math.random() * 1024 * 1024),
}))

export const Default: Story = {
  args: {
    columns: sampleColumns,
    data: sampleData,
    searchable: true,
    pageSize: 10,
  },
}

export const FillViewport: Story = {
  args: {
    columns: sampleColumns,
    data: sampleData,
    searchable: true,
    pageSize: 10,
    fillViewport: true,
  },
}

export const NoData: Story = {
  args: {
    columns: sampleColumns,
    data: [],
    searchable: true,
  },
}

export const SmallDataset: Story = {
  args: {
    columns: sampleColumns,
    data: sampleData.slice(0, 3),
    searchable: false,
  },
}
