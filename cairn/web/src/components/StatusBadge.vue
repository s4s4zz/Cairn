<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{ value: string }>();

const labels: Record<string, string> = {
  created: "待开始",
  ingesting: "源码接入",
  preprocessing: "项目预处理",
  static_scanning: "静态扫描",
  semantic_auditing: "语义审计",
  dynamic_verifying: "动态验证",
  machine_review: "机器复核",
  human_review: "人工复核",
  reporting: "生成报告",
  completed: "已完成",
  completed_with_warnings: "完成（有警告）",
  cancelling: "取消中",
  cancelled: "已取消",
  failed: "失败",
  success: "成功",
  partial: "部分完成",
  ready: "就绪",
  rejected: "已驳回",
  expired: "已过期",
  creating: "创建中",
  candidate: "候选",
  validating: "验证中",
  machine_confirmed: "机器已确认",
  awaiting_human_review: "等待人工复核",
  confirmed: "已确认",
  accepted_risk: "已接受风险",
  verified: "已验证",
  unverified: "未验证",
  not_applicable: "不适用",
  active: "启用",
  inactive: "停用",
  succeeded: "成功",
  running: "运行中",
  queued: "排队中",
  claimed: "已领取",
  skipped: "已跳过",
  inconclusive: "无法判定",
};

const tone = computed(() => {
  if (["completed", "ready", "confirmed", "success", "succeeded", "verified", "active"].includes(props.value)) return "success";
  if (["failed", "rejected", "down"].includes(props.value)) return "danger";
  // `skipped` is a coverage gap, not a neutral outcome: it must not read with
  // the same weight as a stage that simply has not started yet.
  if (["completed_with_warnings", "partial", "skipped", "accepted_risk", "awaiting_human_review", "inconclusive", "degraded"].includes(props.value)) return "warning";
  if (["cancelled", "expired", "not_applicable", "inactive", "unknown"].includes(props.value)) return "neutral";
  return "info";
});
</script>

<template>
  <span class="badge" :class="`badge--${tone}`">{{ labels[value] || value }}</span>
</template>
