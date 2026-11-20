// Shared helpers for platform components: locale-driven re-rendering, focus utilities, common styles.
import { onLocaleChange } from "@cs/sdk";
import { css, type ReactiveController, type ReactiveControllerHost } from "lit";

/** Re-renders the host whenever the locale or a catalog changes. */
export class LocaleController implements ReactiveController {
  private readonly host: ReactiveControllerHost;
  private off: (() => void) | undefined;

  constructor(host: ReactiveControllerHost) {
    this.host = host;
    host.addController(this);
  }

  hostConnected(): void {
    this.off = onLocaleChange(() => {
      this.host.requestUpdate();
    });
  }

  hostDisconnected(): void {
    this.off?.();
    this.off = undefined;
  }
}

/** Focus ring and visually-hidden utility shared by all components. Uses design tokens only. */
export const baseStyles = css`
  :host {
    font-family: var(--cs-font-family);
    font-size: var(--cs-font-size-md);
    line-height: var(--cs-line-height-normal);
    color: var(--cs-color-text);
  }
  :focus-visible {
    outline: var(--cs-focus-ring-width) solid var(--cs-color-focus-ring);
    outline-offset: var(--cs-focus-ring-offset);
  }
  .visually-hidden {
    position: absolute !important;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    clip-path: inset(50%);
    white-space: nowrap;
    border: 0;
  }
`;

const FOCUSABLE =
  'a[href], area[href], button, input:not([type="hidden"]), select, textarea, iframe, [tabindex], [contenteditable=""], [contenteditable="true"]';

function isDisabledOrHidden(el: Element): boolean {
  if (el.hasAttribute("hidden") || el.hasAttribute("inert")) return true;
  if ((el as HTMLElement & { disabled?: unknown }).disabled === true) return true;
  return el.getAttribute("aria-hidden") === "true" && !(el instanceof HTMLSlotElement);
}

/**
 * Tabbable elements under `root` in DOM order, descending into open shadow roots and through slots
 * (assigned elements), so a focus trap sees the same order as the browser's sequential navigation.
 */
export function tabbableElements(root: Element | ShadowRoot): HTMLElement[] {
  const out: HTMLElement[] = [];
  const visit = (el: Element): void => {
    if (el instanceof HTMLSlotElement) {
      const assigned = el.assignedElements({ flatten: true });
      for (const a of assigned.length > 0 ? assigned : Array.from(el.children)) visit(a);
      return;
    }
    if (isDisabledOrHidden(el)) return;
    if (el.shadowRoot) {
      if (el instanceof HTMLElement && el.matches(FOCUSABLE) && el.tabIndex >= 0) out.push(el);
      for (const c of Array.from(el.shadowRoot.children)) visit(c);
      return;
    }
    if (el instanceof HTMLElement && el.matches(FOCUSABLE) && el.tabIndex >= 0) out.push(el);
    for (const c of Array.from(el.children)) visit(c);
  };
  for (const c of Array.from(root.children)) visit(c);
  return out;
}

/** The focused element, descending through shadow roots. */
export function deepActiveElement(doc: Document = document): Element | null {
  let a: Element | null = doc.activeElement;
  while (a?.shadowRoot?.activeElement) a = a.shadowRoot.activeElement;
  return a;
}
