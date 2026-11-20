import { LitElement, css, html, nothing, type TemplateResult } from "lit";
import { baseStyles } from "./shared";
import "./cs-spinner";

export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";

/**
 * Button wrapping a native <button> (keyboard activation with Enter/Space, focus, and the button
 * role come from the platform).
 * - Focus is delegated to the inner button; the focus ring uses the focus-ring token.
 * - `label` sets the accessible name for icon-only buttons.
 * - `busy`: stays focusable, sets aria-busy and aria-disabled, ignores activation, shows a spinner.
 * - `disabled`: native disabled (removed from the tab order, not activatable).
 * - `type="submit" | "reset"` submits or resets the closest ancestor form.
 * - Minimum target size 40×40 CSS px (WCAG 2.2 SC 2.5.8 requires 24).
 */
export class CsButton extends LitElement {
  static override shadowRootOptions: ShadowRootInit = { ...LitElement.shadowRootOptions, delegatesFocus: true };

  static override properties = {
    variant: { type: String, reflect: true },
    type: { type: String },
    disabled: { type: Boolean, reflect: true },
    busy: { type: Boolean, reflect: true },
    label: { type: String },
  };

  static override styles = [
    baseStyles,
    css`
      :host {
        display: inline-block;
      }
      button {
        box-sizing: border-box;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: var(--cs-space-2);
        min-height: var(--cs-target-min);
        min-width: var(--cs-target-min);
        padding: 0 var(--cs-space-4);
        border-radius: var(--cs-radius-md);
        border: 1px solid transparent;
        font: inherit;
        font-weight: var(--cs-font-weight-medium);
        cursor: pointer;
        transition: background-color var(--cs-motion-duration-fast) var(--cs-motion-easing-standard);
      }
      :host([variant="primary"]) button {
        background: var(--cs-color-primary);
        color: var(--cs-color-on-primary);
      }
      :host([variant="primary"]) button:hover:not(:disabled) {
        background: var(--cs-color-primary-hover);
      }
      :host([variant="danger"]) button {
        background: var(--cs-color-danger);
        color: var(--cs-color-on-danger);
      }
      :host([variant="danger"]) button:hover:not(:disabled) {
        background: var(--cs-color-danger-hover);
      }
      :host([variant="secondary"]) button {
        background: var(--cs-color-bg);
        color: var(--cs-color-primary);
        border-color: var(--cs-color-border-strong);
      }
      :host([variant="ghost"]) button {
        background: transparent;
        color: var(--cs-color-primary);
      }
      :host([variant="secondary"]) button:hover:not(:disabled),
      :host([variant="ghost"]) button:hover:not(:disabled) {
        background: var(--cs-color-surface);
      }
      button:disabled,
      button[aria-disabled="true"] {
        cursor: not-allowed;
        opacity: 0.6;
      }
      @media (forced-colors: active) {
        button {
          border-color: ButtonText;
        }
      }
    `,
  ];

  declare variant: ButtonVariant;
  declare type: "button" | "submit" | "reset";
  declare disabled: boolean;
  declare busy: boolean;
  declare label: string | undefined;

  constructor() {
    super();
    this.variant = "secondary";
    this.type = "button";
    this.disabled = false;
    this.busy = false;
    this.label = undefined;
  }

  override render(): TemplateResult {
    return html`<button
      part="button"
      type="button"
      ?disabled=${this.disabled}
      aria-disabled=${this.busy ? "true" : nothing}
      aria-busy=${this.busy ? "true" : nothing}
      aria-label=${this.label ?? nothing}
      @click=${this.onClick}
    >
      ${this.busy ? html`<cs-spinner size="small" decorative></cs-spinner>` : nothing}<slot></slot>
    </button>`;
  }

  private onClick(e: MouseEvent): void {
    if (this.disabled || this.busy) {
      e.preventDefault();
      e.stopImmediatePropagation();
      return;
    }
    if (this.type === "submit" || this.type === "reset") {
      const form = this.closest("form");
      if (!form) return;
      if (this.type === "submit") form.requestSubmit();
      else form.reset();
    }
  }
}

if (!customElements.get("cs-button")) customElements.define("cs-button", CsButton);

declare global {
  interface HTMLElementTagNameMap {
    "cs-button": CsButton;
  }
}
