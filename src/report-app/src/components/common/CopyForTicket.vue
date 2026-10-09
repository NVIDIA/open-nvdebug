<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

<template>
  <button @click="copy" class="nv-btn nv-btn--sm" :title="title">
    {{ copied ? 'Copied!' : label }}
  </button>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { copyToClipboard } from '@/composables/useCopyForTicket'

const props = withDefaults(defineProps<{
  text: string
  label?: string
  title?: string
}>(), {
  label: 'Copy for Ticket',
  title: 'Copy formatted text to clipboard',
})

const copied = ref(false)

async function copy() {
  const success = await copyToClipboard(props.text)
  if (success) {
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  }
}
</script>
