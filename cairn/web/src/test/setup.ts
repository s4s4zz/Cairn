import { afterEach } from "vitest";

class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

Object.defineProperty(globalThis, "ResizeObserver", {
  value: ResizeObserverStub,
  writable: true,
});

afterEach(() => {
  document.body.innerHTML = "";
  document.cookie = "cairn_csrf=; Max-Age=0; path=/";
});
