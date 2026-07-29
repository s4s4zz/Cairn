import { onBeforeUnmount, ref } from "vue";

import { auditRunApi } from "@/api/resources";
import type { AuditRunEventSnapshot } from "@/types/api";

export function useAuditRunEvents(runId: string, onEvent: (event: AuditRunEventSnapshot) => void) {
  const state = ref<"idle" | "connecting" | "connected" | "disconnected">("idle");
  let source: EventSource | null = null;

  function parse(event: MessageEvent<string>): void {
    try {
      onEvent(JSON.parse(event.data) as AuditRunEventSnapshot);
    } catch {
      // A malformed event is ignored; the stream remains useful for later events.
    }
  }

  function connect(): void {
    if (source) return;
    state.value = "connecting";
    source = new EventSource(auditRunApi.eventsUrl(runId), { withCredentials: true });
    source.onopen = () => { state.value = "connected"; };
    source.addEventListener("audit-run", parse as EventListener);
    source.onerror = () => { state.value = "disconnected"; };
  }

  function disconnect(): void {
    source?.close();
    source = null;
    state.value = "idle";
  }

  onBeforeUnmount(disconnect);
  return { state, connect, disconnect };
}
