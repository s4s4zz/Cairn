import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ModelProviderStatus, ModelSummary } from "@/types/api";

const modelProviderApi = vi.hoisted(() => ({
  get: vi.fn(),
  update: vi.fn(),
  models: vi.fn(),
}));

vi.mock("@/api/resources", () => ({ modelProviderApi }));

import SettingsView from "./SettingsView.vue";

const saved: ModelProviderStatus = {
  configured: true,
  provider: "anthropic",
  base_url: "https://api.anthropic.com",
  model: "claude-sonnet-4-5",
  api_key_configured: true,
  updated_at: "2026-07-29T00:00:00Z",
};

// Deliberately share no substring with the saved model. A native <datalist>
// filters its suggestions against the pre-filled input, which hid every one of
// these behind an "已获取 2 个模型" notice.
const discovered: ModelSummary[] = [
  { id: "gpt-4o", display_name: "GPT-4o" },
  { id: "o3-mini", display_name: null },
];

beforeEach(() => {
  vi.clearAllMocks();
  modelProviderApi.get.mockResolvedValue(saved);
  modelProviderApi.models.mockResolvedValue({ models: discovered });
});

async function renderView() {
  const wrapper = mount(SettingsView);
  await flushPromises();
  return wrapper;
}

describe("SettingsView", () => {
  it("offers every fetched model even when the saved one pre-fills the input", async () => {
    const wrapper = await renderView();
    const input = wrapper.get("#provider-model").element as HTMLInputElement;
    expect(input.value).toBe("claude-sonnet-4-5");

    await wrapper.get(".model-input .button--secondary").trigger("click");
    await flushPromises();

    const options = wrapper.findAll(".model-input .select option");
    expect(options.map((option) => option.text())).toEqual([
      "选择模型（2）",
      "GPT-4o",
      "o3-mini",
    ]);
    // None of them is the saved model, so the picker holds its placeholder
    // rather than reporting an unrelated entry as selected, and the saved
    // model survives the fetch.
    const select = wrapper.get(".model-input .select").element as HTMLSelectElement;
    expect(select.value).toBe("");
    expect(input.value).toBe("claude-sonnet-4-5");
    wrapper.unmount();
  });

  it("writes the picked model into the input", async () => {
    const wrapper = await renderView();
    await wrapper.get(".model-input .button--secondary").trigger("click");
    await flushPromises();

    const select = wrapper.get(".model-input .select");
    (select.element as HTMLSelectElement).value = "o3-mini";
    await select.trigger("change");

    const input = wrapper.get("#provider-model").element as HTMLInputElement;
    expect(input.value).toBe("o3-mini");
    expect((select.element as HTMLSelectElement).value).toBe("o3-mini");
    wrapper.unmount();
  });

  it("hides the picker until models are fetched", async () => {
    const wrapper = await renderView();
    expect(wrapper.find(".model-input .select").exists()).toBe(false);
    wrapper.unmount();
  });

  it("prefills a Base URL per provider and clears it for bearer gateways", async () => {
    const wrapper = await renderView();
    const buttons = wrapper.findAll(".provider-switch button");
    expect(buttons.map((button) => button.text())).toEqual([
      "OpenAI",
      "Anthropic",
      "Anthropic Key",
    ]);
    const baseUrl = () =>
      (wrapper.get("#provider-base-url").element as HTMLInputElement).value;

    await buttons[0].trigger("click");
    expect(baseUrl()).toBe("https://api.openai.com");

    // The official API is the one with a canonical host; a bearer deployment
    // is a third-party gateway, so the operator supplies the URL.
    await buttons[2].trigger("click");
    expect(baseUrl()).toBe("https://api.anthropic.com");

    await buttons[1].trigger("click");
    expect(baseUrl()).toBe("");
    wrapper.unmount();
  });

  it("refuses to fetch models before the Base URL is usable", async () => {
    const wrapper = await renderView();
    const buttons = wrapper.findAll(".provider-switch button");
    // The saved provider is already anthropic, and selectProvider is a no-op
    // on the active one, so switch away before switching back to blank it.
    await buttons[0].trigger("click");
    await buttons[1].trigger("click");

    await wrapper.get(".model-input .button--secondary").trigger("click");
    await flushPromises();

    expect(modelProviderApi.models).not.toHaveBeenCalled();
    expect(wrapper.text()).toContain("请先填写 Base URL");
    wrapper.unmount();
  });
});
