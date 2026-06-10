import type { Meta, StoryObj } from '@storybook/vue3'
import Skeleton from './Skeleton.vue'

const meta: Meta<typeof Skeleton> = {
  title: 'Common/Skeleton',
  component: Skeleton,
  argTypes: {
    variant: { control: 'select', options: ['card', 'table-row', 'chart', 'text-block'] },
  },
}

export default meta
type Story = StoryObj<typeof Skeleton>

export const Card: Story = { args: { variant: 'card' } }
export const TableRow: Story = { args: { variant: 'table-row' } }
export const Chart: Story = { args: { variant: 'chart' } }
export const TextBlock: Story = { args: { variant: 'text-block' } }
