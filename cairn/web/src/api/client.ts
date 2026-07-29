export const API_BASE = (import.meta.env.VITE_API_BASE || "/api/v1").replace(/\/$/, "");
export const SERVICE_BASE = (import.meta.env.VITE_SERVICE_BASE || "").replace(/\/$/, "");

type QueryValue = string | number | boolean | null | undefined;

export interface RequestOptions extends Omit<RequestInit, "body"> {
  body?: BodyInit | null;
  json?: unknown;
  query?: Record<string, QueryValue>;
  service?: boolean;
}

interface ApiErrorBody {
  error_code?: string;
  message?: string;
  request_id?: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;

  constructor(status: number, body: ApiErrorBody, fallback: string) {
    super(body.message || fallback);
    this.name = "ApiError";
    this.status = status;
    this.code = body.error_code || `http_${status}`;
    this.requestId = body.request_id;
  }
}

let csrfToken = "";

export function setCsrfToken(token: string): void {
  csrfToken = token;
}

export function clearCsrfToken(): void {
  csrfToken = "";
}

function readCookie(name: string): string {
  if (typeof document === "undefined") return "";
  const prefix = `${name}=`;
  const item = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(prefix));
  return item ? decodeURIComponent(item.slice(prefix.length)) : "";
}

function buildUrl(path: string, query?: Record<string, QueryValue>, base = API_BASE): string {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  const url = `${base}${normalized}`;
  if (!query) return url;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const serialized = params.toString();
  return serialized ? `${url}?${serialized}` : url;
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { json, query, service, headers: providedHeaders, ...requestInit } = options;
  const headers = new Headers(providedHeaders);
  headers.set("Accept", "application/json");

  let body = options.body;
  if (json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(json);
  }

  const method = (options.method || "GET").toUpperCase();
  if (!new Set(["GET", "HEAD", "OPTIONS"]).has(method)) {
    const token = csrfToken || readCookie("cairn_csrf");
    if (token) headers.set("X-CSRF-Token", token);
  }

  const response = await fetch(buildUrl(path, query, service ? SERVICE_BASE : API_BASE), {
    ...requestInit,
    method,
    body,
    headers,
    credentials: "include",
  });

  if (!response.ok) {
    let errorBody: ApiErrorBody = {};
    try {
      errorBody = (await response.json()) as ApiErrorBody;
    } catch {
      errorBody = {};
    }
    if (response.status === 401 && typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("cairn:unauthorized"));
    }
    throw new ApiError(response.status, errorBody, response.statusText || "请求失败");
  }

  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) return (await response.text()) as T;
  return (await response.json()) as T;
}

export function apiUrl(path: string, query?: Record<string, QueryValue>): string {
  return buildUrl(path, query);
}
