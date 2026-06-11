import type { Meta, StoryObj } from '@storybook/vue3'
import ServiceBadge from './ServiceBadge.vue'

const meta: Meta<typeof ServiceBadge> = {
  title: 'Common/ServiceBadge',
  component: ServiceBadge,
  argTypes: {
    service: {
      control: 'select',
      options: ['redfish', 'ssh', 'ipmi', 'health_check', 'host', 'bmc', 'preflight'],
    },
  },
}

export default meta
type Story = StoryObj<typeof ServiceBadge>

export const Redfish: Story = { args: { service: 'redfish' } }
export const SSH: Story = { args: { service: 'ssh' } }
export const IPMI: Story = { args: { service: 'ipmi' } }
export const Host: Story = { args: { service: 'host' } }
export const HealthCheck: Story = { args: { service: 'health_check' } }
export const BMC: Story = { args: { service: 'bmc' } }
