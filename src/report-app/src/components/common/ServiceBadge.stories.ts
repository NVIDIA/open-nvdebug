// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
