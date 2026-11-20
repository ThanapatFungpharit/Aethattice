// Localization (spec §14.3, §14.6). Every user-facing string goes through t() from day one.
import { CORE_ERROR_CODES, isCoreErrorCode, type CoreErrorCode, type ErrorCode } from "./errors";

export type MessageParams = Readonly<Record<string, string | number>>;
export type Catalog = Readonly<Record<string, string>>;

type ErrorKeys = `error.${CoreErrorCode}.title` | `error.${CoreErrorCode}.description`;

const errorMessages: Record<CoreErrorCode, readonly [title: string, description: string]> = {
  invalid_request: ["The request was not valid", "Check the highlighted fields and try again."],
  unauthenticated: ["You are signed out", "Sign in again to continue."],
  permission_denied: ["You do not have permission", "Ask the owner or an administrator for access."],
  not_found: ["Not found", "The item does not exist or you do not have access to it."],
  method_not_allowed: ["This action is not supported", "The action cannot be performed on this item."],
  conflict: ["The change conflicts with the current state", "Refresh to see the latest state, then try again."],
  resource_trashed: ["The item is in the trash", "Restore it from the trash to make changes."],
  precondition_failed: ["The item was changed by someone else", "Reload it to get the latest version, then try again."],
  payload_too_large: ["The upload is too large", "Choose a smaller file or split the content."],
  unsupported_media_type: ["This file type is not supported", "Choose a different file type."],
  idempotency_mismatch: ["The request was already used for a different change", "Start the action again."],
  locked: ["The item is locked", "A retention rule, legal hold or lock prevents this change."],
  rate_limited: ["Too many requests", "Wait a moment and try again."],
  quota_exceeded: ["Storage quota exceeded", "Free up space or ask an administrator for more."],
  internal: ["Something went wrong", "Try again. If the problem continues, contact support."],
  dependency_unavailable: ["A required service is unavailable", "Try again later."],
  unavailable: ["The service is unavailable", "The service may be busy or under maintenance. Try again later."],
  timeout: ["The request timed out", "Try again. If it was a change, check whether it was applied."],
  outcome_unknown: ["The result is unknown", "The change may have been applied. Retrying is safe."],
};

const generatedErrors = Object.fromEntries(
  CORE_ERROR_CODES.flatMap((c) => [
    [`error.${c}.title`, errorMessages[c][0]],
    [`error.${c}.description`, errorMessages[c][1]],
  ]),
) as Record<ErrorKeys, string>;

/** English catalog: the source of truth for core message keys. */
export const EN_MESSAGES = {
  ...generatedErrors,
  "error.app.title": "The application reported a problem",
  "error.app.description": "Try again. If the problem continues, contact support.",
  "error.request_id": "Reference: {id}",
  "error.request_id_label": "Reference:",
  "error.copy_request_id": "Copy reference",
  "error.copied": "Reference copied",
  "error.dismiss": "Dismiss",
  "error.field_errors": "Problems with this request:",
  "spinner.loading": "Loading…",
  "dialog.close": "Close",
  "field.required": "required",
} as const satisfies Catalog;

export type CoreMessageKey = keyof typeof EN_MESSAGES;

export const DEFAULT_LOCALE = "en";

const catalogs = new Map<string, Record<string, string>>([[DEFAULT_LOCALE, { ...EN_MESSAGES }]]);
let currentLocale = DEFAULT_LOCALE;
const listeners = new Set<(locale: string) => void>();

function normalize(locale: string): string {
  return locale.trim().toLowerCase();
}

/** Adds (or overrides) messages for a locale. Applications and the shell register their own keys. */
export function registerMessages(locale: string, messages: Catalog): void {
  const key = normalize(locale);
  catalogs.set(key, { ...(catalogs.get(key) ?? {}), ...messages });
  if (key === currentLocale || key === currentLocale.split("-")[0]) notify();
}

export function setLocale(locale: string): void {
  const next = normalize(locale);
  if (next === currentLocale) return;
  currentLocale = next;
  notify();
}

export function getLocale(): string {
  return currentLocale;
}

/** Subscribes to locale or catalog changes; returns an unsubscribe function. */
export function onLocaleChange(listener: (locale: string) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function notify(): void {
  for (const l of listeners) l(currentLocale);
}

/** True when the key exists in the current locale chain (locale, language, English). */
export function hasMessage(key: string): boolean {
  return lookup(key) !== undefined;
}

function lookup(key: string): string | undefined {
  const lang = currentLocale.split("-")[0] ?? currentLocale;
  for (const loc of [currentLocale, lang, DEFAULT_LOCALE]) {
    const msg = catalogs.get(loc)?.[key];
    if (msg !== undefined) return msg;
  }
  return undefined;
}

/**
 * Translates `key` with `{name}` placeholders replaced by `params`.
 * Falls back from `th-TH` to `th` to English; a missing key returns the key itself so it is visible in review.
 */
export function t(key: CoreMessageKey | (string & {}), params?: MessageParams): string {
  const msg = lookup(key) ?? key;
  if (!params) return msg;
  return msg.replace(/\{([a-zA-Z0-9_]+)\}/g, (whole, name: string) => {
    const v = params[name];
    return v === undefined ? whole : String(v);
  });
}

/** Message keys for a problem's localized title and description. */
export function problemMessageKeys(code: ErrorCode): { title: CoreMessageKey; description: CoreMessageKey } {
  if (isCoreErrorCode(code)) return { title: `error.${code}.title`, description: `error.${code}.description` };
  return { title: "error.app.title", description: "error.app.description" };
}
