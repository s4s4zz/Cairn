<script setup lang="ts">
import { ChevronLeft, ChevronRight } from "@lucide/vue";

const props = defineProps<{ total: number; offset: number; limit: number }>();
const emit = defineEmits<{ change: [offset: number] }>();

function move(delta: number): void {
  emit("change", Math.max(0, props.offset + delta * props.limit));
}
</script>

<template>
  <nav v-if="total > limit" class="pagination" aria-label="分页">
    <span>第 {{ offset + 1 }}–{{ Math.min(offset + limit, total) }} 条，共 {{ total }} 条</span>
    <div>
      <button class="icon-button" type="button" title="上一页" :disabled="offset === 0" @click="move(-1)"><ChevronLeft :size="17" /></button>
      <button class="icon-button" type="button" title="下一页" :disabled="offset + limit >= total" @click="move(1)"><ChevronRight :size="17" /></button>
    </div>
  </nav>
</template>
