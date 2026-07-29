<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import type { editor } from "monaco-editor";
import EditorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker";

const props = withDefaults(defineProps<{ code: string; language?: string; startLine?: number; highlightLine?: number }>(), {
  language: "java",
  startLine: 1,
  highlightLine: 1,
});

const container = ref<HTMLDivElement | null>(null);
const loading = ref(true);
let instance: editor.IStandaloneCodeEditor | null = null;
let monacoModule: typeof import("monaco-editor/esm/vs/editor/editor.api") | null = null;

const workerGlobal = globalThis as typeof globalThis & {
  MonacoEnvironment?: { getWorker: (_moduleId: string, _label: string) => Worker };
};
workerGlobal.MonacoEnvironment ||= { getWorker: () => new EditorWorker() };

async function createEditor(): Promise<void> {
  if (!container.value) return;
  loading.value = true;
  monacoModule ||= await import("monaco-editor/esm/vs/editor/editor.api");
  await import("monaco-editor/esm/vs/basic-languages/java/java.contribution");
  instance = monacoModule.editor.create(container.value, {
    value: props.code,
    language: props.language,
    readOnly: true,
    domReadOnly: true,
    minimap: { enabled: false },
    lineNumbers: (line) => String(line + props.startLine - 1),
    glyphMargin: false,
    folding: false,
    lineDecorationsWidth: 8,
    lineNumbersMinChars: 4,
    renderLineHighlight: "all",
    scrollBeyondLastLine: false,
    automaticLayout: true,
    fontSize: 12,
    fontFamily: "SFMono-Regular, Consolas, Liberation Mono, monospace",
    wordWrap: "off",
    padding: { top: 10, bottom: 10 },
    overviewRulerLanes: 0,
    scrollbar: { verticalScrollbarSize: 9, horizontalScrollbarSize: 9 },
  });
  const relativeLine = Math.max(1, props.highlightLine - props.startLine + 1);
  instance.setPosition({ lineNumber: relativeLine, column: 1 });
  instance.revealLineInCenter(relativeLine);
  loading.value = false;
}

watch(() => props.code, (code) => {
  instance?.setValue(code);
  const relativeLine = Math.max(1, props.highlightLine - props.startLine + 1);
  instance?.setPosition({ lineNumber: relativeLine, column: 1 });
  instance?.revealLineInCenter(relativeLine);
});

onMounted(() => { void createEditor(); });
onBeforeUnmount(() => instance?.dispose());
</script>

<template>
  <div class="code-viewer">
    <div ref="container" class="code-viewer__editor" />
    <div v-if="loading" class="code-viewer__loading"><LoaderCircle class="spin" :size="20" />加载源码视图</div>
  </div>
</template>

<style scoped>
.code-viewer { position: relative; width: 100%; height: 380px; overflow: hidden; background: #fff; border: 1px solid var(--line); border-radius: 0 0 7px 7px; }
.code-viewer__editor { width: 100%; height: 100%; }
.code-viewer__loading { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; gap: 8px; color: var(--muted); background: #fff; font-size: 11px; }
@media (max-width: 620px) { .code-viewer { height: 320px; } }
</style>
