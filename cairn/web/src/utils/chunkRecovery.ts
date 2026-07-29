const RELOAD_MARKER = "cairn:stale-asset-reload";

function errorDescription(reason: unknown): string {
  if (reason instanceof Error) return `${reason.name}: ${reason.message}`;
  return typeof reason === "string" ? reason : "";
}

export function isStaleAssetError(reason: unknown): boolean {
  const description = errorDescription(reason).toLowerCase();
  return [
    "failed to fetch dynamically imported module",
    "error loading dynamically imported module",
    "importing a module script failed",
    "loading chunk",
    "chunkloaderror",
    "preloaderror",
  ].some((fragment) => description.includes(fragment));
}

export interface StaleAssetRecoveryOptions {
  storage?: Storage;
  reload?: () => void;
}

/**
 * Reload once when an already-open workbench asks for a chunk removed by a
 * newer deployment. The session marker prevents a genuinely missing resource
 * or network outage from creating an infinite reload loop.
 */
export function recoverFromStaleAssetError(
  reason: unknown,
  options: StaleAssetRecoveryOptions = {},
): boolean {
  if (!isStaleAssetError(reason)) return false;

  const storage = options.storage ?? window.sessionStorage;
  if (storage.getItem(RELOAD_MARKER) === "1") return false;

  storage.setItem(RELOAD_MARKER, "1");
  (options.reload ?? (() => window.location.reload()))();
  return true;
}

export function clearStaleAssetReloadMarker(
  storage: Storage = window.sessionStorage,
): void {
  storage.removeItem(RELOAD_MARKER);
}
