<script setup lang="ts">
import { X } from "@lucide/vue";

withDefaults(defineProps<{ open: boolean; title: string; width?: "small" | "medium" | "large" }>(), { width: "medium" });
defineEmits<{ close: [] }>();
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="modal-backdrop" @mousedown.self="$emit('close')">
      <section class="modal" :class="`modal--${width}`" role="dialog" aria-modal="true" :aria-label="title">
        <header class="modal__header">
          <h2>{{ title }}</h2>
          <button class="icon-button" type="button" title="关闭" aria-label="关闭" @click="$emit('close')"><X :size="18" /></button>
        </header>
        <div class="modal__body"><slot /></div>
        <footer v-if="$slots.footer" class="modal__footer"><slot name="footer" /></footer>
      </section>
    </div>
  </Teleport>
</template>
