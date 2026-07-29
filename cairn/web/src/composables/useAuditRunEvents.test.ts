import { defineComponent, h } from "vue";
import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";

import type { AuditRunEventSnapshot } from "@/types/api";
import { useAuditRunEvents } from "./useAuditRunEvents";

class EventSourceStub {
  static instance: EventSourceStub | null = null;
  readonly listeners = new Map<string, EventListener>();
  readonly url: string;
  readonly withCredentials: boolean;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  close = vi.fn();

  constructor(url: string | URL, options?: EventSourceInit) {
    this.url = String(url);
    this.withCredentials = options?.withCredentials ?? false;
    EventSourceStub.instance = this;
  }

  addEventListener(type: string, callback: EventListener): void {
    this.listeners.set(type, callback);
  }
}

describe("useAuditRunEvents", () => {
  it("subscribes to the backend audit-run event and closes on unmount", async () => {
    vi.stubGlobal("EventSource", EventSourceStub);
    const received: AuditRunEventSnapshot[] = [];
    const component = defineComponent({
      setup() {
        const stream = useAuditRunEvents("run-1", (event) => received.push(event));
        stream.connect();
        return () => h("div", stream.state.value);
      },
    });
    const wrapper = mount(component);
    const source = EventSourceStub.instance;
    expect(source?.url).toBe("/api/v1/audit-runs/run-1/events");
    expect(source?.withCredentials).toBe(true);

    const payload: AuditRunEventSnapshot = {
      audit_run_id: "run-1", status: "human_review", current_stage: "human_review", progress: 90,
      warning_count: 1, failure_code: null, failure_reason: null, task_counts: { succeeded: 4 },
      finding_counts: { awaiting_human_review: 1 }, coverage_warning_count: 1, completed_at: null,
    };
    source?.listeners.get("audit-run")?.(new MessageEvent("audit-run", { data: JSON.stringify(payload) }));
    expect(received).toEqual([payload]);

    wrapper.unmount();
    expect(source?.close).toHaveBeenCalledOnce();
    vi.unstubAllGlobals();
  });
});
