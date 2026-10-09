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
import StatusBadge from './StatusBadge.vue'

const meta: Meta<typeof StatusBadge> = {
  title: 'Common/StatusBadge',
  component: StatusBadge,
  argTypes: {
    status: {
      control: 'select',
      options: ['success', 'degraded', 'error', 'partial', 'skipped', 'not_ran', 'unknown', 'pass', 'fail', 'warning'],
    },
  },
}

export default meta
type Story = StoryObj<typeof StatusBadge>

export const Success: Story = { args: { status: 'success' } }
export const Degraded: Story = { args: { status: 'degraded' } }
export const Error: Story = { args: { status: 'error' } }
export const Partial: Story = { args: { status: 'partial' } }
export const Skipped: Story = { args: { status: 'skipped' } }
export const NotRan: Story = { args: { status: 'not_ran' } }
export const Pass: Story = { args: { status: 'pass' } }
export const Fail: Story = { args: { status: 'fail' } }
