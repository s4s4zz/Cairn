<script setup lang="ts">
import { AlertTriangle, Inbox, LoaderCircle, RotateCw } from "@lucide/vue";

withDefaults(
  defineProps<{
    kind: "loading" | "error" | "empty";
    title?: string;
    message?: string;
    retryable?: boolean;
  }>(),
  { title: "", message: "", retryable: false },
);

defineEmits<{ retry: [] }>();
</script>

<template>
  <div class="state-panel" :class="`state-panel--${kind}`" role="status">
    <LoaderCircle v-if="kind === 'loading'" class="spin" :size="24" />
    <AlertTriangle v-else-if="kind === 'error'" :size="24" />
    <Inbox v-else :size="24" />
    <div>
      <strong>{{ title || (kind === "loading" ? "正在加载" : kind === "error" ? "加载失败" : "暂无数据") }}</strong>
      <p v-if="message">{{ message }}</p>
    </div>
    <button v-if="kind === 'error' && retryable" class="button button--secondary button--small" type="button" @click="$emit('retry')">
      <RotateCw :size="15" />
      重试
    </button>
  </div>
</template>
