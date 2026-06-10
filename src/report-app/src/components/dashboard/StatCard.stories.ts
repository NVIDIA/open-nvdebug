import type { Meta, StoryObj } from '@storybook/vue3'
import StatCard from './StatCard.vue'

const meta: Meta<typeof StatCard> = {
  title: 'Dashboard/StatCard',
  component: StatCard,
}

export default meta
type Story = StoryObj<typeof StatCard>

export const Default: Story = {
  args: { label: 'Total DUTs', value: 5, color: 'green' },
}
export const Clickable: Story = {
  args: { label: 'Failed', value: 3, subtitle: 'of 50 collectors', color: 'red', clickable: true },
}
export const Large: Story = {
  args: { label: 'Total Runtime', value: '2h 15m 30s', color: 'slate' },
}
