import { t } from "@cs/sdk";
import { LitElement, css, html, nothing, type PropertyValues, type TemplateResult } from "lit";
import { LocaleController, baseStyles, deepActiveElement, tabbableElements } from "./shared";

export type DialogCloseReason = "escape" | "close-button" | "backdrop" | "api";

export interface DialogCloseDetail {
  readonly reason: DialogCloseReason;
}

/**
 * Modal dialog (WAI-ARIA APG dialog pattern).
 * - role="dialog", aria-modal="true", labelled by its heading.
 * - On open, focus moves to the first slotted element with `autofocus`, else the first tabbable
 *   element in the body/footer, else the dialog itself. Tab/Shift+Tab cycle inside the dialog;
 *   focus that escapes (e.g. via pointer) is pulled back.
 * - Escape, the close button and a backdrop click request closing: a cancelable `cs-request-close`
 *   event is dispatched first; if not cancelled the dialog closes and fires `cs-close`.
 * - On close, focus returns to the element that had it when the dialog opened.
 */
export class CsDialog extends LitElement {
  static override properties = {
    open: { type: Boolean, reflect: true },
    heading: { type: String },
  };

  static override styles = [
    baseStyles,
    css`
      :host {
        display: contents;
      }
      .backdrop {
        position: fixed;
        inset: 0;
        background: var(--cs-color-backdrop);
        z-index: 1000;
      }
      .panel {
        position: fixed;
        z-index: 1001;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        box-sizing: border-box;
        width: min(32rem, calc(100vw - 2 * var(--cs-space-4)));
        max-height: calc(100vh - 2 * var(--cs-space-4));
        overflow: auto;
        padding: var(--cs-space-5);
        border-radius: var(--cs-radius-lg);
        background: var(--cs-color-surface-raised);
        color: var(--cs-color-text);
        border: 1px solid var(--cs-color-border);
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.25);
      }
      header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: var(--cs-space-3);
        margin-bottom: var(--cs-space-4);
      }
      h2 {
        margin: 0;
        font-size: var(--cs-font-size-lg);
        line-height: var(--cs-line-height-tight);
      }
      .close {
        flex: none;
        min-width: var(--cs-target-min);
        min-height: var(--cs-target-min);
        border: none;
        border-radius: var(--cs-radius-md);
        background: transparent;
        color: var(--cs-color-text);
        font: inherit;
        font-size: var(--cs-font-size-lg);
        cursor: pointer;
      }
      .close:hover {
        background: var(--cs-color-surface);
      }
      footer {
        display: flex;
        justify-content: flex-end;
        gap: var(--cs-space-2);
        margin-top: var(--cs-space-5);
      }
      footer:not(:has(*)) {
        display: none;
      }
    `,
  ];

  declare open: boolean;
  declare heading: string;

  private returnFocus: HTMLElement | null = null;
  private readonly onDocFocusIn = (e: FocusEvent): void => {
    if (!this.open) return;
    if (!e.composedPath().includes(this)) this.focusInitial();
  };

  constructor() {
    super();
    this.open = false;
    this.heading = "";
    new LocaleController(this);
  }

  override connectedCallback(): void {
    super.connectedCallback();
    document.addEventListener("focusin", this.onDocFocusIn);
    // Listening on the host catches keydown from both shadow content and slotted light-DOM content.
    this.addEventListener("keydown", this.onKeydown);
  }

  override disconnectedCallback(): void {
    document.removeEventListener("focusin", this.onDocFocusIn);
    this.removeEventListener("keydown", this.onKeydown);
    super.disconnectedCallback();
  }

  /** Opens the dialog. */
  show(): void {
    this.open = true;
  }

  /** Closes the dialog without a cancelable request. */
  close(): void {
    if (!this.open) return;
    this.open = false;
    this.dispatchEvent(new CustomEvent<DialogCloseDetail>("cs-close", { detail: { reason: "api" }, bubbles: true, composed: true }));
  }

  /** Asks to close; listeners may cancel `cs-request-close`. Returns true when the dialog closed. */
  requestClose(reason: DialogCloseReason): boolean {
    const ev = new CustomEvent<DialogCloseDetail>("cs-request-close", { detail: { reason }, cancelable: true, bubbles: true, composed: true });
    if (!this.dispatchEvent(ev)) return false;
    this.open = false;
    this.dispatchEvent(new CustomEvent<DialogCloseDetail>("cs-close", { detail: { reason }, bubbles: true, composed: true }));
    return true;
  }

  protected override willUpdate(changed: PropertyValues<this>): void {
    if (changed.has("open") && this.open) {
      const active = deepActiveElement();
      this.returnFocus = active instanceof HTMLElement && !this.contains(active) ? active : null;
    }
  }

  protected override updated(changed: PropertyValues<this>): void {
    if (!changed.has("open")) return;
    if (this.open) {
      this.focusInitial();
    } else if (changed.get("open") === true) {
      const target = this.returnFocus;
      this.returnFocus = null;
      if (target?.isConnected) target.focus();
    }
  }

  override render(): TemplateResult | typeof nothing {
    if (!this.open) return nothing;
    // Backdrop click is a pointer convenience; Escape and the close button are the keyboard equivalents.
    // eslint-disable-next-line lit-a11y/click-events-have-key-events
    return html`<div class="backdrop" part="backdrop" @click=${this.onBackdrop}></div>
      <div
        class="panel"
        part="panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="heading"
        tabindex="-1"
      >
        <header>
          <h2 id="heading" part="heading">${this.heading}</h2>
          <button class="close" part="close" type="button" aria-label=${t("dialog.close")} @click=${this.onCloseButton}>
            <span aria-hidden="true">×</span>
          </button>
        </header>
        <div class="body" part="body"><slot></slot></div>
        <footer part="footer"><slot name="footer"></slot></footer>
      </div>`;
  }

  private get panel(): HTMLElement | null {
    return this.renderRoot.querySelector<HTMLElement>(".panel");
  }

  /** Tabbable elements in visual order: close button, body, footer. */
  private tabbables(): HTMLElement[] {
    const panel = this.panel;
    return panel ? tabbableElements(panel) : [];
  }

  private focusInitial(): void {
    const panel = this.panel;
    if (!panel) return;
    const auto = this.querySelector<HTMLElement>("[autofocus]");
    if (auto) {
      auto.focus();
      return;
    }
    const closeBtn = this.renderRoot.querySelector<HTMLElement>(".close");
    const first = this.tabbables().find((el) => el !== closeBtn);
    (first ?? panel).focus();
  }

  private readonly onKeydown = (e: KeyboardEvent): void => {
    if (!this.open) return;
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      this.requestClose("escape");
      return;
    }
    if (e.key !== "Tab") return;
    const items = this.tabbables();
    e.preventDefault();
    if (items.length === 0) {
      this.panel?.focus();
      return;
    }
    const active = deepActiveElement();
    const idx = items.findIndex((el) => el === active || el.shadowRoot?.contains(active) === true);
    const next = e.shiftKey ? (idx <= 0 ? items.length - 1 : idx - 1) : idx === -1 || idx === items.length - 1 ? 0 : idx + 1;
    items[next]?.focus();
  };

  private onCloseButton(): void {
    this.requestClose("close-button");
  }

  private onBackdrop(): void {
    this.requestClose("backdrop");
  }
}

if (!customElements.get("cs-dialog")) customElements.define("cs-dialog", CsDialog);

declare global {
  interface HTMLElementTagNameMap {
    "cs-dialog": CsDialog;
  }
}
