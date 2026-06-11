import type { Meta, StoryObj } from '@storybook/vue3'
import StatusPieChart from './StatusPieChart.vue'

const meta: Meta<typeof StatusPieChart> = {
  title: 'Charts/StatusPieChart',
  component: StatusPieChart,
  tags: ['autodocs'],
}
export default meta

type Story = StoryObj<typeof StatusPieChart>

export const Default: Story = {
  args: {
    counts: { success: 42, error: 5, partial: 3, skipped: 2, not_ran: 8 },
  },
}

export const AllSuccess: Story = {
  args: {
    counts: { success: 60, error: 0, partial: 0, skipped: 0, not_ran: 0 },
  },
}

export const HighFailure: Story = {
  args: {
    counts: { success: 10, error: 30, partial: 5, skipped: 5, not_ran: 10 },
  },
}

export const Empty: Story = {
  args: {
    counts: { success: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 },
  },
}
