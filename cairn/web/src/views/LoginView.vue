<script setup lang="ts">
import { AlertCircle, LoaderCircle, LockKeyhole, ShieldCheck, UserRound } from "@lucide/vue";
import { ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import { useAuthStore } from "@/stores/auth";
import { errorMessage } from "@/utils";

const auth = useAuthStore();
const route = useRoute();
const router = useRouter();
const username = ref("");
const password = ref("");
const error = ref("");

async function submit(): Promise<void> {
  error.value = "";
  try {
    await auth.login(username.value.trim(), password.value);
    const redirect = typeof route.query.redirect === "string" && route.query.redirect.startsWith("/") ? route.query.redirect : "/";
    await router.replace(redirect);
  } catch (reason) {
    error.value = errorMessage(reason);
  }
}
</script>

<template>
  <main class="login-page">
    <section class="login-context" aria-label="Cairn Java 审计工作台">
      <div class="login-brand"><ShieldCheck :size="28" /><div><strong>Cairn</strong><span>Java Audit Workbench</span></div></div>
      <div class="login-context__status">
        <span class="status-dot" />
        <p>受控审计环境</p>
      </div>
    </section>

    <section class="login-form-wrap">
      <form class="login-form" @submit.prevent="submit">
        <header><h1>登录工作台</h1><p>使用分配给你的本地账户继续。</p></header>
        <div v-if="error" class="inline-error" role="alert"><AlertCircle :size="16" />{{ error }}</div>
        <div class="field">
          <label for="username">用户名</label>
          <div class="input-with-icon"><UserRound :size="16" /><input id="username" v-model="username" class="input" autocomplete="username" required autofocus /></div>
        </div>
        <div class="field">
          <label for="password">密码</label>
          <div class="input-with-icon"><LockKeyhole :size="16" /><input id="password" v-model="password" class="input" type="password" autocomplete="current-password" required /></div>
        </div>
        <button class="button button--full" type="submit" :disabled="auth.busy || !username || !password">
          <LoaderCircle v-if="auth.busy" class="spin" :size="16" />
          {{ auth.busy ? "正在验证" : "登录" }}
        </button>
      </form>
    </section>
  </main>
</template>

<style scoped>
.login-page { display: grid; min-height: 100vh; grid-template-columns: minmax(280px, 0.8fr) minmax(420px, 1.2fr); background: #fff; }
.login-context { display: flex; min-height: 100vh; flex-direction: column; justify-content: space-between; padding: 42px; color: #edf5f1; background: #17201d; border-right: 1px solid #313c38; }
.login-brand { display: flex; align-items: center; gap: 13px; }
.login-brand > div { display: grid; gap: 3px; }
.login-brand strong { font-size: 19px; }
.login-brand span { color: #92a39b; font-size: 10px; text-transform: uppercase; }
.login-context__status { display: flex; align-items: center; gap: 9px; color: #9baaa3; font-size: 11px; }
.login-context__status p { margin: 0; }
.status-dot { width: 7px; height: 7px; background: #54b291; border-radius: 50%; box-shadow: 0 0 0 4px rgba(84,178,145,.12); }
.login-form-wrap { display: flex; min-height: 100vh; align-items: center; justify-content: center; padding: 32px; }
.login-form { display: grid; width: min(100%, 360px); gap: 18px; }
.login-form header { margin-bottom: 6px; }
.login-form h1 { margin-bottom: 7px; color: #202a25; font-size: 24px; }
.login-form header p { margin: 0; color: #6a766f; font-size: 12px; }
.input-with-icon { position: relative; }
.input-with-icon > svg { position: absolute; z-index: 1; top: 11px; left: 11px; color: #78847e; }
.input-with-icon .input { padding-left: 36px; }
@media (max-width: 720px) {
  .login-page { display: block; background: #f4f6f5; }
  .login-context { min-height: 0; padding: 20px 22px; flex-direction: row; align-items: center; }
  .login-context__status { display: none; }
  .login-form-wrap { min-height: calc(100vh - 73px); padding: 24px; }
}
</style>
