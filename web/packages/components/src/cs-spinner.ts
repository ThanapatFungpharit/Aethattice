import { t } from "@cs/sdk";
import { LitElement, css, html, type TemplateResult } from "lit";
import { LocaleController, baseStyles } from "./shared";

/**
 * Indeterminate progress indicator.
 * - Announces its label through a polite live region (role="status").
 * - `decorative`: hidden from assistive technology, for use inside controls that already expose
 *   their busy state (e.g. cs-button with aria-busy).
 * - Under prefers-reduced-motion the arc does not rotate; a static ring is shown instead.
 */
export class CsSpinner extends LitElement {
  static override properties = {
    label: { type: String },
    size: { type: String, reflect: true },
    decorative: { type: Boolean, reflect: true },
  };

  static override styles = [
    baseStyles,
    css`
      :host {
        display: inline-flex;
        align-items: center;
        gap: var(--cs-space-2);
        vertical-align: middle;
      }
      .ring {
        box-sizing: border-box;
        width: 1.5rem;
        height: 1.5rem;
        border-radius: var(--cs-radius-full);
        border: 3px solid var(--cs-color-border);
        border-top-color: var(--cs-color-primary);
        animation: spin var(--cs-motion-duration-spin) linear infinite;
      }
      :host([size="small"]) .ring {
        width: 1em;
        height: 1em;
        border-width: 2px;
        border-color: currentColor;
        border-top-color: transparent;
      }
      @keyframes spin {
        to {
          transform: rotate(360deg);
        }
      }
      @media (prefers-reduced-motion: reduce) {
        .ring {
          animation: none;
          border-style: dotted;
        }
      }
    `,
  ];

  declare label: string | undefined;
  declare size: "small" | "medium";
  declare decorative: boolean;

  constructor() {
    super();
    this.label = undefined;
    this.size = "medium";
    this.decorative = false;
    new LocaleController(this);
  }

  override render(): TemplateResult {
    const label = this.label ?? t("spinner.loading");
    if (this.decorative) return html`<span class="ring" part="ring" aria-hidden="true"></span>`;
    return html`<span role="status" aria-live="polite" part="status">
      <span class="ring" part="ring" aria-hidden="true"></span>
      <span class="visually-hidden">${label}</span>
    </span>`;
  }
}

if (!customElements.get("cs-spinner")) customElements.define("cs-spinner", CsSpinner);

declare global {
  interface HTMLElementTagNameMap {
    "cs-spinner": CsSpinner;
  }
}
