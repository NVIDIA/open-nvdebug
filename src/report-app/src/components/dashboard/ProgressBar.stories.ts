import type { Meta, StoryObj } from '@storybook/vue3'
import ProgressBar from './ProgressBar.vue'

const meta: Meta<typeof ProgressBar> = {
  title: 'Dashboard/ProgressBar',
  component: ProgressBar,
}

export default meta
type Story = StoryObj<typeof ProgressBar>

export const AllSuccess: Story = { args: { counts: { success: 50, error: 0, partial: 0, skipped: 0, not_ran: 0 } } }
export const Mixed: Story = { args: { counts: { success: 30, error: 5, partial: 3, skipped: 10, not_ran: 2 } } }
export const AllError: Story = { args: { counts: { success: 0, error: 20, partial: 0, skipped: 0, not_ran: 0 } } }
export const Empty: Story = { args: { counts: { success: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 } } }
