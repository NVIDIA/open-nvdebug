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
