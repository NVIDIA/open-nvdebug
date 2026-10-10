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
import ProgressBar from './ProgressBar.vue'

const meta: Meta<typeof ProgressBar> = {
  title: 'Dashboard/ProgressBar',
  component: ProgressBar,
}

export default meta
type Story = StoryObj<typeof ProgressBar>

export const AllSuccess: Story = { args: { counts: { success: 50, degraded: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 } } }
export const Mixed: Story = { args: { counts: { success: 27, degraded: 3, error: 5, partial: 3, skipped: 10, not_ran: 2 } } }
export const AllDegraded: Story = { args: { counts: { success: 0, degraded: 20, error: 0, partial: 0, skipped: 0, not_ran: 0 } } }
export const AllError: Story = { args: { counts: { success: 0, degraded: 0, error: 20, partial: 0, skipped: 0, not_ran: 0 } } }
export const Empty: Story = { args: { counts: { success: 0, degraded: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 } } }
