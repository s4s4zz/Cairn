<script setup lang="ts">
import { KeyRound, Plus, UserCheck, UserX } from "@lucide/vue";
import { onMounted, reactive, ref } from "vue";

import { userApi } from "@/api/resources";
import ModalDialog from "@/components/ModalDialog.vue";
import PageHeader from "@/components/PageHeader.vue";
import PaginationBar from "@/components/PaginationBar.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import type { User, UserRole } from "@/types/api";
import { errorMessage, formatDate } from "@/utils";

const items = ref<User[]>([]);
const loading = ref(true);
const error = ref("");
const total = ref(0);
const offset = ref(0);
const limit = 25;
const createOpen = ref(false);
const passwordOpen = ref(false);
const selected = ref<User | null>(null);
const saving = ref(false);
const formError = ref("");
const createForm = reactive({ username: "", password: "", role: "viewer" as UserRole });
const password = ref("");

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  try { const page = await userApi.list({ limit, offset: offset.value }); items.value = page.items; total.value = page.meta.total; } catch (reason) { error.value = errorMessage(reason); } finally { loading.value = false; }
}

async function createUser(): Promise<void> {
  saving.value = true; formError.value = "";
  try { await userApi.create({ ...createForm, username: createForm.username.trim() }); createOpen.value = false; Object.assign(createForm, { username: "", password: "", role: "viewer" }); await load(); } catch (reason) { formError.value = errorMessage(reason); } finally { saving.value = false; }
}

async function updateRole(user: User, role: UserRole): Promise<void> {
  try { const updated = await userApi.update(user.id, { role }); Object.assign(user, updated); } catch (reason) { error.value = errorMessage(reason); await load(); }
}

async function toggleActive(user: User): Promise<void> {
  try { const updated = await userApi.update(user.id, { is_active: !user.is_active }); Object.assign(user, updated); } catch (reason) { error.value = errorMessage(reason); }
}

function openPassword(user: User): void { selected.value = user; password.value = ""; formError.value = ""; passwordOpen.value = true; }
async function setPassword(): Promise<void> {
  if (!selected.value) return;
  saving.value = true; formError.value = "";
  try { await userApi.setPassword(selected.value.id, password.value); passwordOpen.value = false; } catch (reason) { formError.value = errorMessage(reason); } finally { saving.value = false; }
}
async function changePage(value: number): Promise<void> { offset.value = value; await load(); }
onMounted(load);
</script>

<template>
  <PageHeader title="用户管理" description="管理单租户本地账户、角色、状态与密码。"><template #actions><button class="button" type="button" @click="createOpen = true"><Plus :size="15" />新增用户</button></template></PageHeader>
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error && !items.length" kind="error" :message="error" retryable @retry="load" />
  <div v-else class="table-wrap"><div v-if="error" class="inline-error user-error">{{ error }}</div><table class="data-table users-table"><thead><tr><th style="width:25%">用户</th><th style="width:17%">角色</th><th style="width:14%">状态</th><th>最近登录</th><th style="width:18%">创建时间</th><th style="width:90px"></th></tr></thead><tbody>
    <tr v-for="user in items" :key="user.id"><td><span class="cell-main">{{ user.username }}</span><span class="cell-sub mono">{{ user.id }}</span></td><td><select class="select role-select" :value="user.role" :aria-label="`${user.username} 的角色`" @change="updateRole(user, ($event.target as HTMLSelectElement).value as UserRole)"><option value="admin">管理员</option><option value="auditor">审计员</option><option value="reviewer">复核员</option><option value="viewer">只读用户</option></select></td><td><StatusBadge :value="user.is_active ? 'active' : 'inactive'" /></td><td class="muted nowrap">{{ formatDate(user.last_login_at) }}</td><td class="muted nowrap">{{ formatDate(user.created_at) }}</td><td><div class="row-actions"><button class="icon-button" type="button" :title="user.is_active ? '停用用户' : '启用用户'" @click="toggleActive(user)"><UserX v-if="user.is_active" :size="16" /><UserCheck v-else :size="16" /></button><button class="icon-button" type="button" title="重置密码" @click="openPassword(user)"><KeyRound :size="16" /></button></div></td></tr>
  </tbody></table><PaginationBar :total="total" :offset="offset" :limit="limit" @change="changePage" /></div>

  <ModalDialog :open="createOpen" title="新增用户" @close="createOpen = false"><form id="create-user" class="user-form" @submit.prevent="createUser"><div class="field"><label for="new-username">用户名</label><input id="new-username" v-model="createForm.username" class="input" minlength="3" maxlength="64" autocomplete="off" required /></div><div class="field"><label for="new-role">角色</label><select id="new-role" v-model="createForm.role" class="select"><option value="admin">管理员</option><option value="auditor">审计员</option><option value="reviewer">复核员</option><option value="viewer">只读用户</option></select></div><div class="field"><label for="new-password">初始密码</label><input id="new-password" v-model="createForm.password" class="input" type="password" minlength="12" autocomplete="new-password" required /></div><div v-if="formError" class="inline-error">{{ formError }}</div></form><template #footer><button class="button button--secondary" type="button" @click="createOpen = false">取消</button><button class="button" type="submit" form="create-user" :disabled="saving">{{ saving ? "创建中" : "创建用户" }}</button></template></ModalDialog>
  <ModalDialog :open="passwordOpen" :title="`重置 ${selected?.username || ''} 的密码`" width="small" @close="passwordOpen = false"><form id="reset-password" class="user-form" @submit.prevent="setPassword"><div class="field"><label for="reset-value">新密码</label><input id="reset-value" v-model="password" class="input" type="password" minlength="12" autocomplete="new-password" required /></div><div v-if="formError" class="inline-error">{{ formError }}</div></form><template #footer><button class="button button--secondary" type="button" @click="passwordOpen = false">取消</button><button class="button" type="submit" form="reset-password" :disabled="saving">保存密码</button></template></ModalDialog>
</template>

<style scoped>
.user-error { margin: 10px; }
.role-select { min-height: 32px; }
.user-form { display: grid; gap: 15px; }
@media (max-width: 760px) { .users-table { min-width: 850px; } }
</style>
