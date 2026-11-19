import { ApiClient, RetryPolicy, hasMessage, type Clock } from "@cs/sdk";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import "./cs-shell-app";
import type { CsShellApp } from "./cs-shell-app";
import { SAMPLE_PROBLEMS } from "./dev-errors";
import { SHELL_MESSAGES_EN, registerShellMessages } from "./messages";
import { checkReadiness } from "./readiness";

const instantClock: Clock = { now: () => 0, sleep: () => Promise.resolve() };

function clientWith(fetchImpl: () => Promise<Response>): ApiClient {
  return new ApiClient({ baseUrl: "https://shell.test", fetch: vi.fn(fetchImpl), clock: instantClock, retryPolicy: new RetryPolicy() });
}

async function mountShell(client: ApiClient): Promise<CsShellApp> {
  const el = document.createElement("cs-shell-app");
  el.client = client;
  document.body.appendChild(el);
  await el.refreshReadiness();
  return el;
}

function root(el: Element): ShadowRoot {
  if (!el.shadowRoot) throw new Error("no shadow root");
  return el.shadowRoot;
}

beforeAll(() => {
  registerShellMessages();
});

afterEach(() => {
  document.body.innerHTML = "";
  location.hash = "";
});

describe("shell messages", () => {
  it("are all registered", () => {
    for (const k of Object.keys(SHELL_MESSAGES_EN)) expect(hasMessage(k), k).toBe(true);
  });
});

describe("checkReadiness", () => {
  it("is ready on 200", async () => {
    const r = await checkReadiness(clientWith(() => Promise.resolve(new Response("{}", { status: 200, headers: { "X-Request-Id": "r1" } }))));
    expect(r).toEqual({ state: "ready", requestId: "r1" });
  });

  it("reports the 503 problem from /readyz", async () => {
    const body = { type: "https://errors.x/v1/unavailable", title: "Unavailable", status: 503, code: "unavailable", retryable: true, request_id: "rq", detail: "domain cs_identity unreachable" };
    const fetchImpl = vi.fn(() => Promise.resolve(new Response(JSON.stringify(body), { status: 503, headers: { "Content-Type": "application/problem+json" } })));
    const r = await checkReadiness(new ApiClient({ baseUrl: "https://shell.test", fetch: fetchImpl, clock: instantClock }));
    expect(r.state).toBe("not_ready");
    expect(r.state === "not_ready" && r.problem.code).toBe("unavailable");
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("handles an absent backend (network failure) as unavailable", async () => {
    const r = await checkReadiness(clientWith(() => Promise.reject(new TypeError("Failed to fetch"))));
    expect(r.state === "not_ready" && r.problem.code).toBe("unavailable");
  });
});

describe("cs-shell-app", () => {
  it("has header, navigation, notification and main regions", async () => {
    const el = await mountShell(clientWith(() => Promise.resolve(new Response(null, { status: 200 }))));
    const r = root(el);
    expect(r.querySelector("header")).not.toBeNull();
    expect(r.querySelector("nav")?.getAttribute("aria-label")).toBe("Global");
    expect(r.querySelector("main#main")).not.toBeNull();
    const notes = r.querySelector("section.notifications");
    expect(notes?.getAttribute("aria-labelledby")).toBe("notifications-heading");
    expect(notes?.querySelector('[aria-live="polite"]')).not.toBeNull();
    expect(r.querySelector(".skip-link")?.textContent).toBe("Skip to main content");
  });

  it("renders ready status", async () => {
    const el = await mountShell(clientWith(() => Promise.resolve(new Response(null, { status: 200 }))));
    expect(root(el).querySelector(".ready")?.textContent).toBe("The service is ready.");
  });

  it("renders the error banner when the backend is absent", async () => {
    const el = await mountShell(clientWith(() => Promise.reject(new TypeError("Failed to fetch"))));
    const banner = root(el).querySelector("cs-error-banner");
    expect(banner?.problem?.code).toBe("unavailable");
    await banner?.updateComplete;
    expect(banner?.shadowRoot?.querySelector(".title")?.textContent).toBe("The service is unavailable");
  });

  it("opens the launcher placeholder dialog", async () => {
    const el = await mountShell(clientWith(() => Promise.resolve(new Response(null, { status: 200 }))));
    const launcher = root(el).querySelector<HTMLElement>("cs-button.launcher");
    launcher?.shadowRoot?.querySelector("button")?.click();
    await el.updateComplete;
    const dialog = root(el).querySelector("cs-dialog");
    expect(dialog?.open).toBe(true);
    expect(dialog?.heading).toBe("Applications");
  });

  it("routes #/dev/errors to the dev page with sample banners", async () => {
    location.hash = "#/dev/errors";
    const el = await mountShell(clientWith(() => Promise.resolve(new Response(null, { status: 200 }))));
    const dev = root(el).querySelector("cs-dev-errors");
    expect(dev).not.toBeNull();
    await dev?.updateComplete;
    const banners = dev?.shadowRoot?.querySelectorAll("cs-error-banner") ?? [];
    expect(banners.length).toBe(SAMPLE_PROBLEMS.length + 1);
  });
});
