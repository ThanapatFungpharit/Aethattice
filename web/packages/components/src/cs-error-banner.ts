import { problemMessageKeys, t, type Problem } from "@cs/sdk";
import { LitElement, css, html, nothing, type TemplateResult } from "lit";
import { LocaleController, baseStyles } from "./shared";

/**
 * Renders a Problem (App. D) for end users.
 * - Title and description are localized by `code` (core codes) or a generic application message
 *   (`app.*` codes); the server's `title` is never shown.
 * - The server's `detail` is shown only for client errors (4xx), where D.1 guarantees it is localized
 *   and contains nothing the caller may not see. For 5xx it is never shown: internals stay in logs.
 *   Field errors (`errors[].detail`) follow the same rule.
 * - `request_id` is shown as a support reference with a copy button.
 * - role="alert" so the problem is announced when it appears or changes.
 * - `dismissible` adds a dismiss button that fires a cancelable `cs-dismiss` event.
 */
export class CsErrorBanner extends LitElement {
  static override properties = {
    problem: { attribute: false },
    dismissible: { type: Boolean, reflect: true },
    copied: { state: true },
  };

  static override styles = [
    baseStyles,
    css`
      :host {
        display: block;
      }
      .banner {
        display: flex;
        gap: var(--cs-space-3);
        align-items: flex-start;
        padding: var(--cs-space-3) var(--cs-space-4);
        border: 1px solid var(--cs-color-danger);
        border-left-width: 4px;
        border-radius: var(--cs-radius-md);
        background: var(--cs-color-danger-surface);
        color: var(--cs-color-danger-text);
      }
      .icon {
        flex: none;
        width: 1.25rem;
        height: 1.25rem;
        margin-top: 0.15rem;
        fill: currentColor;
      }
      .content {
        flex: 1;
        min-width: 0;
      }
      .title {
        margin: 0;
        font-weight: var(--cs-font-weight-bold);
      }
      p {
        margin: var(--cs-space-1) 0 0;
      }
      ul {
        margin: var(--cs-space-1) 0 0;
        padding-inline-start: var(--cs-space-5);
      }
      .ref {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--cs-space-2);
        font-size: var(--cs-font-size-sm);
      }
      code {
        font-family: var(--cs-font-family-mono);
        user-select: all;
        overflow-wrap: anywhere;
      }
      button {
        min-height: 24px;
        min-width: 24px;
        padding: var(--cs-space-1) var(--cs-space-2);
        border: 1px solid currentColor;
        border-radius: var(--cs-radius-sm);
        background: transparent;
        color: inherit;
        font: inherit;
        cursor: pointer;
      }
      .dismiss {
        flex: none;
        min-width: var(--cs-target-min);
        min-height: var(--cs-target-min);
        border: none;
        font-size: var(--cs-font-size-lg);
      }
    `,
  ];

  declare problem: Problem | undefined;
  declare dismissible: boolean;
  declare copied: boolean;

  constructor() {
    super();
    this.problem = undefined;
    this.dismissible = false;
    this.copied = false;
    new LocaleController(this);
  }

  override willUpdate(changed: Map<PropertyKey, unknown>): void {
    if (changed.has("problem")) this.copied = false;
  }

  override render(): TemplateResult | typeof nothing {
    const p = this.problem;
    if (!p) return nothing;
    const keys = problemMessageKeys(p.code);
    const clientError = p.status >= 400 && p.status < 500;
    const detail = clientError && p.detail ? p.detail : undefined;
    const fieldErrors = clientError ? (p.errors ?? []).filter((e) => e.detail) : [];
    // navigator.clipboard is absent in insecure contexts even though the DOM types declare it.
    const clipboard = (navigator as { clipboard?: Partial<Clipboard> }).clipboard;
    const canCopy = typeof clipboard?.writeText === "function";

    return html`<div class="banner" part="banner" role="alert">
      <svg class="icon" viewBox="0 0 16 16" aria-hidden="true">
        <path d="M8 1a7 7 0 1 1 0 14A7 7 0 0 1 8 1Zm-.75 3.5v4.5h1.5V4.5h-1.5Zm0 6v1.5h1.5V10.5h-1.5Z" />
      </svg>
      <div class="content">
        <p class="title" part="title">${t(keys.title)}</p>
        <p class="description" part="description">${t(keys.description)}</p>
        ${detail ? html`<p class="detail" part="detail">${detail}</p>` : nothing}
        ${fieldErrors.length > 0
          ? html`<p>${t("error.field_errors")}</p>
              <ul class="field-errors">
                ${fieldErrors.map((e) => html`<li>${e.detail}</li>`)}
              </ul>`
          : nothing}
        ${p.request_id
          ? html`<p class="ref" part="reference">
              <span>${t("error.request_id_label")} <code>${p.request_id}</code></span>
              ${canCopy
                ? html`<button type="button" class="copy" @click=${this.copy}>${t("error.copy_request_id")}</button>`
                : nothing}
              <span class="visually-hidden" role="status">${this.copied ? t("error.copied") : ""}</span>
            </p>`
          : nothing}
      </div>
      ${this.dismissible
        ? html`<button type="button" class="dismiss" aria-label=${t("error.dismiss")} @click=${this.dismiss}>
            <span aria-hidden="true">×</span>
          </button>`
        : nothing}
    </div>`;
  }

  private async copy(): Promise<void> {
    const id = this.problem?.request_id;
    if (!id) return;
    try {
      await navigator.clipboard.writeText(id);
      this.copied = true;
    } catch {
      this.copied = false;
    }
  }

  private dismiss(): void {
    const ev = new CustomEvent("cs-dismiss", { cancelable: true, bubbles: true, composed: true });
    if (this.dispatchEvent(ev)) this.problem = undefined;
  }
}

if (!customElements.get("cs-error-banner")) customElements.define("cs-error-banner", CsErrorBanner);

declare global {
  interface HTMLElementTagNameMap {
    "cs-error-banner": CsErrorBanner;
  }
}
