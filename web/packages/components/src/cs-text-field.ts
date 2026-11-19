import { t } from "@cs/sdk";
import { LitElement, css, html, nothing, type PropertyValues, type TemplateResult } from "lit";
import { live } from "lit/directives/live.js";
import { LocaleController, baseStyles } from "./shared";

export type TextFieldType = "text" | "email" | "password" | "search" | "tel" | "url";

/**
 * Labelled single-line text input.
 * - The visible <label> is programmatically associated with the input (SC 1.3.1, 2.5.3, 3.3.2).
 * - `description` and `error` are linked with aria-describedby; `error` also sets aria-invalid and
 *   aria-errormessage. The error text sits in a polite live region so it is announced when it appears.
 * - The visible "required" marker is hidden from AT; `required` sets aria-required via the native attribute.
 * - Errors are conveyed by text and an icon, not colour alone (SC 1.4.1).
 * - Form-associated (ElementInternals) where supported; `input` events bubble from the inner input,
 *   `change` is re-dispatched from the host.
 */
export class CsTextField extends LitElement {
  static formAssociated = true;
  static override shadowRootOptions: ShadowRootInit = { ...LitElement.shadowRootOptions, delegatesFocus: true };

  static override properties = {
    label: { type: String },
    description: { type: String },
    error: { type: String },
    value: { type: String },
    name: { type: String, reflect: true },
    type: { type: String },
    required: { type: Boolean, reflect: true },
    disabled: { type: Boolean, reflect: true },
    readonly: { type: Boolean, reflect: true },
    autocomplete: { type: String },
  };

  static override styles = [
    baseStyles,
    css`
      :host {
        display: block;
      }
      .field {
        display: flex;
        flex-direction: column;
        gap: var(--cs-space-1);
      }
      label {
        font-weight: var(--cs-font-weight-medium);
      }
      .required {
        color: var(--cs-color-text-muted);
        font-weight: var(--cs-font-weight-regular);
      }
      .description {
        color: var(--cs-color-text-muted);
        font-size: var(--cs-font-size-sm);
      }
      input {
        box-sizing: border-box;
        min-height: var(--cs-target-min);
        padding: 0 var(--cs-space-3);
        border: 1px solid var(--cs-color-border-strong);
        border-radius: var(--cs-radius-md);
        background: var(--cs-color-bg);
        color: var(--cs-color-text);
        font: inherit;
      }
      input[aria-invalid="true"] {
        border-color: var(--cs-color-danger);
        border-width: 2px;
      }
      input:disabled {
        opacity: 0.6;
        cursor: not-allowed;
      }
      .error {
        display: flex;
        gap: var(--cs-space-1);
        align-items: flex-start;
        color: var(--cs-color-danger);
        font-size: var(--cs-font-size-sm);
      }
      .error:empty {
        display: none;
      }
      svg {
        flex: none;
        width: 1em;
        height: 1em;
        margin-top: 0.2em;
        fill: currentColor;
      }
    `,
  ];

  declare label: string;
  declare description: string | undefined;
  declare error: string | undefined;
  declare value: string;
  declare name: string | undefined;
  declare type: TextFieldType;
  declare required: boolean;
  declare disabled: boolean;
  declare readonly: boolean;
  declare autocomplete: string | undefined;

  private readonly internals: ElementInternals | undefined;

  constructor() {
    super();
    this.label = "";
    this.description = undefined;
    this.error = undefined;
    this.value = "";
    this.name = undefined;
    this.type = "text";
    this.required = false;
    this.disabled = false;
    this.readonly = false;
    this.autocomplete = undefined;
    this.internals = typeof this.attachInternals === "function" ? this.attachInternals() : undefined;
    new LocaleController(this);
  }

  /** Resets to empty when the owning form resets. */
  formResetCallback(): void {
    this.value = "";
  }

  protected override updated(changed: PropertyValues<this>): void {
    if (changed.has("value")) (this.internals as Partial<ElementInternals> | undefined)?.setFormValue?.(this.value);
  }

  override render(): TemplateResult {
    const describedBy = [this.description ? "description" : "", this.error ? "error" : ""].filter(Boolean).join(" ");
    return html`<div class="field">
      <label for="input" part="label"
        >${this.label}${this.required
          ? html` <span class="required" aria-hidden="true">(${t("field.required")})</span>`
          : nothing}</label
      >
      ${this.description ? html`<div id="description" class="description" part="description">${this.description}</div>` : nothing}
      <input
        id="input"
        part="input"
        .value=${live(this.value)}
        type=${this.type}
        name=${this.name ?? nothing}
        autocomplete=${this.autocomplete ?? nothing}
        ?required=${this.required}
        ?disabled=${this.disabled}
        ?readonly=${this.readonly}
        aria-invalid=${this.error ? "true" : "false"}
        aria-describedby=${describedBy || nothing}
        aria-errormessage=${this.error ? "error" : nothing}
        @input=${this.onInput}
        @change=${this.onChange}
      />
      <div id="error" class="error" part="error" aria-live="polite">${this.error
          ? html`<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1 15 14H1L8 1Zm-.75 5v4h1.5V6h-1.5Zm0 5v1.5h1.5V11h-1.5Z" /></svg><span>${this.error}</span>`
          : nothing}</div>
    </div>`;
  }

  private onInput(e: Event): void {
    this.value = (e.target as HTMLInputElement).value;
  }

  private onChange(): void {
    this.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
  }
}

if (!customElements.get("cs-text-field")) customElements.define("cs-text-field", CsTextField);

declare global {
  interface HTMLElementTagNameMap {
    "cs-text-field": CsTextField;
  }
}
