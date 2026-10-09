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
    counts: { success: 39, degraded: 3, error: 5, partial: 3, skipped: 2, not_ran: 8 },
  },
}

export const AllSuccess: Story = {
  args: {
    counts: { success: 60, degraded: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 },
  },
}

export const HighFailure: Story = {
  args: {
    counts: { success: 10, degraded: 4, error: 26, partial: 5, skipped: 5, not_ran: 10 },
  },
}

export const Empty: Story = {
  args: {
    counts: { success: 0, degraded: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 },
  },
}
