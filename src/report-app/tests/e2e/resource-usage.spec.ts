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

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { expect, test } from './e2e-fixture'

const fixture = (name: string) => readFileSync(resolve('tests/fixtures', name), 'utf8')

async function mockResources(page: import('@playwright/test').Page) {
  const capture = {
    schema_version: '1.0', status: 'closed', worker_count: 16, observation_seconds: 50,
    calls: { enqueued: 3000, worker_completions: 3000, worker_failures: 0, abandoned_before_submission: 0 },
    pool: { active_workers: 0, queued_calls: 0, peak_active_workers: 16, peak_queued_calls: 45 },
    queue: {
      wait_seconds_total: 600, wait_seconds_average: 0.2, wait_seconds_max: 1.9,
      queued_wall_seconds: 40, queued_capacity_worker_seconds: 640,
      queued_active_worker_seconds: 320, saturated_while_queued_seconds: 4,
      runnable_gap_worker_seconds: 320, utilization_while_queued_ratio: 0.5,
      saturation_while_queued_ratio: 0.1,
    },
    workers: { seconds_total: 350, utilization_ratio: 0.4375 },
  }
  const artifact = JSON.parse(fixture('resource_usage.json'))
  artifact.components = { request_capture: capture }
  const samplesWithCapture = (name: string) => fixture(name).trim().split('\n').map((line, index) => {
    const sample = JSON.parse(line)
    sample.components = {
      request_capture: {
        ...capture,
        status: 'running',
        pool: { ...capture.pool, active_workers: 4 + index * 4, queued_calls: 20 - index * 5 },
      },
    }
    return JSON.stringify(sample)
  }).join('\n')
  const payloads = new Map([
    ['resource_usage.json', JSON.stringify(artifact)],
    ['resource_usage_samples.previous.jsonl', samplesWithCapture('resource_usage_samples.previous.jsonl')],
    ['resource_usage_samples.jsonl', samplesWithCapture('resource_usage_samples.jsonl')],
    ['concurrency_scheduler.json', fixture('concurrency_scheduler.json')],
  ])
  await page.route(/\/\.metadata\/(?:resource_usage.*|concurrency_scheduler\.json)$/, async route => {
    const name = new URL(route.request().url()).pathname.split('/').pop() ?? ''
    const body = payloads.get(name)
    await route.fulfill(body === undefined
      ? { status: 404, body: '' }
      : { status: 200, body, contentType: name.endsWith('.json') ? 'application/json' : 'application/x-ndjson' })
  })
}

test('resource analysis is responsive and exposes accessible chart summaries', async ({ page }) => {
  await mockResources(page)
  await page.goto('/#/resources')

  await expect(page.getByRole('heading', { name: 'Resource Usage' })).toBeVisible()
  await expect(page.locator('.resource-signal')).toHaveCount(4)
  await expect(page.locator('.resource-chart[role="img"]')).toHaveCount(9)
  await expect(page.locator('.resource-chart[aria-label*="minimum"]')).toHaveCount(9)
  await expect(page.getByRole('heading', { name: 'Request capture pool' })).toBeVisible()
  await expect(page.getByText('Capture workers', { exact: true })).toBeVisible()
  await expect(page.locator('.resource-chart[aria-label*="worker and queue"]')).toBeVisible()
  await expect(page.locator('.resource-chart[aria-label*="queued utilization"]')).toBeVisible()
  await expect(page.locator('.concurrency-chart[role="img"]')).toHaveCount(1)
  await expect(page.locator('.concurrency-chart[aria-label*="324 of 324"]')).toBeVisible()
  await expect(page.getByText('5 → 6').first()).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true)

  const resourceRoute = page.url()
  await page.locator('.resource-sidebar a[href="#adaptive-concurrency"]').click()
  await expect(page).toHaveURL(resourceRoute)
  await expect(page.locator('#adaptive-concurrency')).toBeInViewport()
  await page.locator('.resource-sidebar a[href="#health"]').click()
  await expect(page).toHaveURL(resourceRoute)
  await expect(page.locator('#health')).toBeInViewport()

  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.locator('.resource-sidebar')).toBeHidden()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true)
})

test('legacy reports show an explicit unavailable state', async ({ page }) => {
  await page.route('**/.metadata/resource_usage.json', route => route.fulfill({ status: 404, body: '' }))
  await page.goto('/#/resources')

  await expect(page.getByText('Resource telemetry unavailable')).toBeVisible()
  await expect(page.getByText(/may predate resource telemetry/)).toBeVisible()
})

test('file URL directory selection loads resource artifacts from the chosen run', async ({ page }) => {
  const runDirectory = mkdtempSync(join(tmpdir(), 'nvdebug-resource-e2e-'))
  mkdirSync(join(runDirectory, '.metadata'), { recursive: true })
  mkdirSync(join(runDirectory, 'DUT_1', 'redfish'), { recursive: true })
  writeFileSync(join(runDirectory, '.metadata', 'resource_usage.json'), fixture('resource_usage.json'))
  writeFileSync(join(runDirectory, '.metadata', 'resource_usage_samples.previous.jsonl'), fixture('resource_usage_samples.previous.jsonl'))
  writeFileSync(join(runDirectory, '.metadata', 'resource_usage_samples.jsonl'), fixture('resource_usage_samples.jsonl'))
  writeFileSync(join(runDirectory, '.metadata', 'concurrency_scheduler.json'), fixture('concurrency_scheduler.json'))
  writeFileSync(join(runDirectory, 'DUT_1', 'redfish', 'Systems.json'), '{"fixture":true}\n')
  const reportUrl = pathToFileURL(resolve('dist/index.html'))
  reportUrl.hash = '/resources'
  try {
    await page.goto(reportUrl.href)

    await expect(page.getByText('Select the collection directory')).toBeVisible()
    await page.locator('input[webkitdirectory]').setInputFiles(runDirectory)

    await expect(page.getByRole('heading', { name: 'Resource Usage' })).toBeVisible()
    await expect(page.getByText('Select the collection directory')).toBeHidden()
    await expect(page.getByText('180.0 MiB').first()).toBeVisible()
    await expect(page.getByText('Retained-file coverage', { exact: true })).toBeVisible()
    await expect(page.locator('.concurrency-chart[aria-label*="324 of 324"]')).toBeVisible()
    expect(await page.evaluate(() => location.protocol)).toBe('file:')
  } finally {
    rmSync(runDirectory, { recursive: true, force: true })
  }
})
