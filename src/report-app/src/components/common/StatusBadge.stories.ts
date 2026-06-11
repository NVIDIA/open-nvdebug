import type { Meta, StoryObj } from '@storybook/vue3'
import StatusBadge from './StatusBadge.vue'

const meta: Meta<typeof StatusBadge> = {
  title: 'Common/StatusBadge',
  component: StatusBadge,
  argTypes: {
    status: {
      control: 'select',
      options: ['success', 'error', 'partial', 'skipped', 'not_ran', 'unknown', 'pass', 'fail', 'warning'],
    },
  },
}

export default meta
type Story = StoryObj<typeof StatusBadge>

export const Success: Story = { args: { status: 'success' } }
export const Error: Story = { args: { status: 'error' } }
export const Partial: Story = { args: { status: 'partial' } }
export const Skipped: Story = { args: { status: 'skipped' } }
export const NotRan: Story = { args: { status: 'not_ran' } }
export const Pass: Story = { args: { status: 'pass' } }
export const Fail: Story = { args: { status: 'fail' } }
