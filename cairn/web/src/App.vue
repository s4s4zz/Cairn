<script setup lang="ts">
import { onBeforeUnmount, onMounted } from "vue";
import { useRouter } from "vue-router";

import AppShell from "@/components/AppShell.vue";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const router = useRouter();

function onUnauthorized(): void {
  if (!auth.isAuthenticated) return;
  auth.clearSession();
  void router.replace({ name: "login", query: { redirect: router.currentRoute.value.fullPath } });
}

onMounted(() => window.addEventListener("cairn:unauthorized", onUnauthorized));
onBeforeUnmount(() => window.removeEventListener("cairn:unauthorized", onUnauthorized));
</script>

<template>
  <RouterView v-if="$route.meta.public" />
  <AppShell v-else>
    <RouterView />
  </AppShell>
</template>
