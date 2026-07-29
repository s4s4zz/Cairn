/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE?: string;
  readonly VITE_SERVICE_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
