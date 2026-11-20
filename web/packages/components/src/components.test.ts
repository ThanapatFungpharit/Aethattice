import { registerMessages, setLocale, synthesizeProblem, type Problem } from "@cs/sdk";
import { afterEach, describe, expect, it, vi } from "vitest";
import { deepActiveElement } from "./shared";
import "./index";
import type { CsButton } from "./cs-button";
import type { CsDialog } from "./cs-dialog";
import type { CsErrorBanner } from "./cs-error-banner";
import type { CsSpinner } from "./cs-spinner";
import type { CsTextField } from "./cs-text-field";

async function mount<K extends keyof HTMLElementTagNameMap>(tag: K, setup?: (el: HTMLElementTagNameMap[K]) => void): Promise<HTMLElementTagNameMap[K]> {
  const el = document.createElement(tag);
  setup?.(el);
  document.body.appendChild(el);
  await (el as unknown as { updateComplete: Promise<unknown> }).updateComplete;
  return el;
}

function shadow(el: Element): ShadowRoot {
  if (!el.shadowRoot) throw new Error("no shadow root");
  return el.shadowRoot;
}

function q<T extends HTMLElement = HTMLElement>(el: Element, sel: string, ctor?: abstract new () => T): T {
  const found = shadow(el).querySelector(sel);
  const expected: abstract new () => HTMLElement = ctor ?? HTMLElement;
  if (!(found instanceof expected)) throw new Error(`missing ${sel}`);
  return found as T;
}

function key(target: EventTarget, k: string, shiftKey = false): KeyboardEvent {
  const e = new KeyboardEvent("keydown", { key: k, shiftKey, bubbles: true, composed: true, cancelable: true });
  target.dispatchEvent(e);
  return e;
}

afterEach(() => {
  document.body.innerHTML = "";
  setLocale("en");
});

describe("cs-spinner", () => {
  it("is a polite status with a localized label", async () => {
    const el = await mount("cs-spinner");
    const status = q(el, '[role="status"]');
    expect(status.getAttribute("aria-live")).toBe("polite");
    expect(status.textContent.trim()).toBe("Loading…");
    expect(q(el, ".ring").getAttribute("aria-hidden")).toBe("true");
  });

  it("uses a custom label", async () => {
    const el = await mount("cs-spinner", (s: CsSpinner) => { s.label = "Checking"; });
    expect(q(el, '[role="status"]').textContent.trim()).toBe("Checking");
  });

  it("is hidden from AT when decorative", async () => {
    const el = await mount("cs-spinner", (s) => { s.decorative = true; });
    expect(shadow(el).querySelector('[role="status"]')).toBeNull();
  });

  it("stops the animation under prefers-reduced-motion", () => {
    const css = (customElements.get("cs-spinner") as unknown as { styles: { cssText?: string }[] }).styles.map((s) => s.cssText ?? "").join("");
    expect(css).toMatch(/prefers-reduced-motion: reduce\)\s*{\s*\.ring\s*{\s*animation: none/);
  });

  it("re-renders when the locale changes", async () => {
    registerMessages("th", { "spinner.loading": "กำลังโหลด…" });
    const el = await mount("cs-spinner");
    setLocale("th");
    await el.updateComplete;
    expect(q(el, '[role="status"]').textContent.trim()).toBe("กำลังโหลด…");
  });
});

describe("cs-button", () => {
  it("renders a native button with the slotted label and delegates focus", async () => {
    const el = await mount("cs-button", (b) => { b.textContent = "Save"; });
    const btn = q(el, "button", HTMLButtonElement);
    expect(btn.type).toBe("button");
    expect((customElements.get("cs-button") as unknown as typeof CsButton).shadowRootOptions.delegatesFocus).toBe(true);
    expect(el.getAttribute("variant")).toBe("secondary");
  });

  it("sets aria-label from label for icon-only buttons", async () => {
    const el = await mount("cs-button", (b) => { b.label = "Close"; });
    expect(q(el, "button").getAttribute("aria-label")).toBe("Close");
  });

  it("disabled uses the native attribute and blocks clicks", async () => {
    const onClick = vi.fn();
    const el = await mount("cs-button", (b) => { b.disabled = true; });
    el.addEventListener("click", onClick);
    q(el, "button").click();
    expect(q(el, "button", HTMLButtonElement).disabled).toBe(true);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("busy stays focusable, exposes aria-busy/aria-disabled and swallows activation", async () => {
    const onClick = vi.fn();
    const el = await mount("cs-button", (b: CsButton) => { b.busy = true; });
    el.addEventListener("click", onClick);
    const btn = q(el, "button", HTMLButtonElement);
    btn.click();
    expect(btn.disabled).toBe(false);
    expect(btn.getAttribute("aria-busy")).toBe("true");
    expect(btn.getAttribute("aria-disabled")).toBe("true");
    expect(q(el, "cs-spinner").hasAttribute("decorative")).toBe(true);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("type=submit submits the enclosing form", async () => {
    const form = document.createElement("form");
    const submit = vi.fn((e: Event) => { e.preventDefault(); });
    form.addEventListener("submit", submit);
    document.body.appendChild(form);
    const el = document.createElement("cs-button");
    el.type = "submit";
    form.appendChild(el);
    await el.updateComplete;
    q(el, "button").click();
    expect(submit).toHaveBeenCalledTimes(1);
  });
});

describe("cs-text-field", () => {
  it("associates label, description and input", async () => {
    const el = await mount("cs-text-field", (f: CsTextField) => {
      f.label = "Email";
      f.description = "We never share it.";
    });
    const label = q(el, "label", HTMLLabelElement);
    const input = q(el, "input", HTMLInputElement);
    expect(label.htmlFor).toBe(input.id);
    expect(label.textContent.trim()).toBe("Email");
    expect(input.getAttribute("aria-describedby")).toBe("description");
    expect(q(el, "#description").textContent).toBe("We never share it.");
    expect(input.getAttribute("aria-invalid")).toBe("false");
    expect(input.hasAttribute("aria-errormessage")).toBe(false);
  });

  it("wires the error with aria-invalid, aria-describedby, aria-errormessage and a live region", async () => {
    const el = await mount("cs-text-field", (f) => {
      f.label = "Name";
      f.description = "Shown to others";
      f.error = "Name is required.";
    });
    const input = q(el, "input", HTMLInputElement);
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(input.getAttribute("aria-describedby")).toBe("description error");
    expect(input.getAttribute("aria-errormessage")).toBe("error");
    const err = q(el, "#error");
    expect(err.getAttribute("aria-live")).toBe("polite");
    expect(err.textContent.trim()).toBe("Name is required.");
    expect(err.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
  });

  it("marks required natively and hides the visual marker from AT", async () => {
    const el = await mount("cs-text-field", (f) => {
      f.label = "Name";
      f.required = true;
    });
    expect(q(el, "input", HTMLInputElement).required).toBe(true);
    expect(q(el, ".required").getAttribute("aria-hidden")).toBe("true");
  });

  it("updates value on input, bubbles input and re-dispatches change", async () => {
    const el = await mount("cs-text-field", (f) => { f.label = "Name"; });
    const changes = vi.fn();
    el.addEventListener("change", changes);
    const input = q(el, "input", HTMLInputElement);
    input.value = "Ada";
    input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    expect(el.value).toBe("Ada");
    expect(changes).toHaveBeenCalledTimes(1);
  });
});

describe("cs-dialog", () => {
  async function openDialog(): Promise<{ dialog: CsDialog; opener: HTMLButtonElement; first: HTMLInputElement; last: HTMLButtonElement }> {
    const opener = document.createElement("button");
    opener.textContent = "Open";
    document.body.appendChild(opener);
    opener.focus();
    const dialog = await mount("cs-dialog", (d) => {
      d.heading = "Rename";
      d.innerHTML = `<input id="first" /><button id="last" slot="footer">OK</button>`;
    });
    dialog.open = true;
    await dialog.updateComplete;
    const first = dialog.querySelector<HTMLInputElement>("#first");
    const last = dialog.querySelector<HTMLButtonElement>("#last");
    if (!first || !last) throw new Error("fixture");
    return { dialog, opener, first, last };
  }

  it("renders nothing while closed", async () => {
    const d = await mount("cs-dialog");
    expect(shadow(d).querySelector('[role="dialog"]')).toBeNull();
  });

  it("is a labelled modal dialog", async () => {
    const { dialog } = await openDialog();
    const panel = q(dialog, '[role="dialog"]');
    expect(panel.getAttribute("aria-modal")).toBe("true");
    expect(panel.getAttribute("aria-labelledby")).toBe("heading");
    expect(q(dialog, "#heading").textContent).toBe("Rename");
    expect(q(dialog, ".close").getAttribute("aria-label")).toBe("Close");
  });

  it("moves focus into the dialog on open", async () => {
    const { first } = await openDialog();
    expect(deepActiveElement()).toBe(first);
  });

  it("honours autofocus", async () => {
    const dialog = await mount("cs-dialog", (d) => {
      d.innerHTML = `<input id="a" /><input id="b" autofocus />`;
    });
    dialog.open = true;
    await dialog.updateComplete;
    expect(deepActiveElement()?.id).toBe("b");
  });

  it("traps Tab and Shift+Tab", async () => {
    const { dialog, first, last } = await openDialog();
    const close = q(dialog, ".close");
    const panel = q(dialog, '[role="dialog"]');
    last.focus();
    expect(key(last, "Tab").defaultPrevented).toBe(true);
    expect(deepActiveElement()).toBe(close);
    key(panel, "Tab");
    expect(deepActiveElement()).toBe(first);
    first.focus();
    key(first, "Tab", true);
    expect(deepActiveElement()).toBe(close);
    key(panel, "Tab", true);
    expect(deepActiveElement()).toBe(last);
  });

  it("pulls focus back when it escapes", async () => {
    const { opener, first } = await openDialog();
    opener.focus();
    expect(deepActiveElement()).toBe(first);
  });

  it("closes on Escape, fires events and restores focus to the opener", async () => {
    const { dialog, opener, first } = await openDialog();
    const closed = vi.fn();
    dialog.addEventListener("cs-close", closed);
    key(first, "Escape");
    await dialog.updateComplete;
    expect(dialog.open).toBe(false);
    expect(closed).toHaveBeenCalledTimes(1);
    expect((closed.mock.calls[0]?.[0] as CustomEvent).detail).toEqual({ reason: "escape" });
    expect(deepActiveElement()).toBe(opener);
  });

  it("stays open when cs-request-close is cancelled", async () => {
    const { dialog, first } = await openDialog();
    dialog.addEventListener("cs-request-close", (e) => { e.preventDefault(); });
    key(first, "Escape");
    await dialog.updateComplete;
    expect(dialog.open).toBe(true);
  });

  it("closes via the close button and the backdrop", async () => {
    const { dialog } = await openDialog();
    q(dialog, ".close").click();
    await dialog.updateComplete;
    expect(dialog.open).toBe(false);
    dialog.show();
    await dialog.updateComplete;
    q(dialog, ".backdrop").click();
    await dialog.updateComplete;
    expect(dialog.open).toBe(false);
  });

  it("focuses the panel when nothing in the body is tabbable", async () => {
    const dialog = await mount("cs-dialog", (d) => { d.textContent = "Just text"; });
    dialog.open = true;
    await dialog.updateComplete;
    expect(deepActiveElement()).toBe(q(dialog, '[role="dialog"]'));
  });
});

describe("cs-error-banner", () => {
  const problem: Problem = {
    type: "https://errors.example.test/v1/not_found",
    title: "SERVER TITLE",
    status: 404,
    code: "not_found",
    detail: "The folder “Plans” does not exist.",
    request_id: "req-123",
    retryable: false,
  };

  it("renders nothing without a problem", async () => {
    const el = await mount("cs-error-banner");
    expect(shadow(el).querySelector('[role="alert"]')).toBeNull();
  });

  it("shows the localized title by code, detail for 4xx and the request id", async () => {
    const el = await mount("cs-error-banner", (b: CsErrorBanner) => { b.problem = problem; });
    const alert = q(el, '[role="alert"]');
    expect(q(el, ".title").textContent).toBe("Not found");
    expect(alert.textContent).not.toContain("SERVER TITLE");
    expect(q(el, ".detail").textContent).toBe(problem.detail);
    expect(q(el, "code").textContent).toBe("req-123");
  });

  it("never shows detail or field errors for 5xx", async () => {
    const el = await mount("cs-error-banner", (b) => {
      b.problem = {
        ...synthesizeProblem("internal"),
        type: "https://errors.example.test/v1/internal",
        detail: "panic at cs_db::pool line 42",
        errors: [{ pointer: "/x", code: "y", detail: "stack trace" }],
        request_id: "r5",
      };
    });
    const text = q(el, '[role="alert"]').textContent;
    expect(text).toContain("Something went wrong");
    expect(text).not.toContain("panic");
    expect(text).not.toContain("stack trace");
    expect(text).toContain("r5");
  });

  it("lists field error details for validation failures", async () => {
    const el = await mount("cs-error-banner", (b) => {
      b.problem = { ...problem, code: "invalid_request", status: 400, errors: [{ pointer: "/name", code: "too_long", detail: "Name is too long." }] };
    });
    expect(q(el, ".field-errors").textContent).toContain("Name is too long.");
  });

  it("uses a generic localized title for application codes", async () => {
    const el = await mount("cs-error-banner", (b) => { b.problem = { ...problem, code: "app.photos.album_full", status: 409 }; });
    expect(q(el, ".title").textContent).toBe("The application reported a problem");
  });

  it("re-localizes when the locale changes", async () => {
    registerMessages("th", { "error.not_found.title": "ไม่พบ" });
    const el = await mount("cs-error-banner", (b) => { b.problem = problem; });
    setLocale("th");
    await el.updateComplete;
    expect(q(el, ".title").textContent).toBe("ไม่พบ");
  });

  it("copies the request id and announces it", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { userAgent: navigator.userAgent, language: navigator.language, clipboard: { writeText } });
    try {
      const el = await mount("cs-error-banner", (b) => { b.problem = problem; });
      q(el, ".copy").click();
      await vi.waitFor(() => {
        expect(writeText).toHaveBeenCalledWith("req-123");
      });
      await el.updateComplete;
      expect(q(el, '.ref [role="status"]').textContent).toBe("Reference copied");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("dismisses unless cs-dismiss is cancelled", async () => {
    const el = await mount("cs-error-banner", (b) => {
      b.problem = problem;
      b.dismissible = true;
    });
    const dismiss = q(el, ".dismiss");
    expect(dismiss.getAttribute("aria-label")).toBe("Dismiss");
    const cancel = (e: Event): void => { e.preventDefault(); };
    el.addEventListener("cs-dismiss", cancel);
    dismiss.click();
    await el.updateComplete;
    expect(el.problem).toBeDefined();
    el.removeEventListener("cs-dismiss", cancel);
    dismiss.click();
    await el.updateComplete;
    expect(el.problem).toBeUndefined();
    expect(shadow(el).querySelector('[role="alert"]')).toBeNull();
  });
});
