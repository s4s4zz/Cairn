import { createApp } from "vue";

import App from "./App.vue";
import router from "./router";
import { pinia } from "./stores";
import "./styles.css";
import {
  clearStaleAssetReloadMarker,
  recoverFromStaleAssetError,
} from "./utils/chunkRecovery";

type VitePreloadErrorEvent = Event & { payload?: unknown };

window.addEventListener("vite:preloadError", (event) => {
  const recovered = recoverFromStaleAssetError(
    (event as VitePreloadErrorEvent).payload,
  );
  if (recovered) event.preventDefault();
});

router.onError((error) => {
  recoverFromStaleAssetError(error);
});

router.afterEach(() => {
  clearStaleAssetReloadMarker();
});

createApp(App).use(pinia).use(router).mount("#app");
