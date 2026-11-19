// Developer page: exercises cs-error-banner with sample Problems and with Problems produced by the
// real ApiClient pipeline against a simulated server (malformed bodies, HTML error pages, network failures).
import "@cs/components";
import { ApiClient, ApiError, RetryPolicy, t, type Problem } from "@cs/sdk";
import { LocaleController } from "@cs/components";
import { LitElement, css, html, nothing, type TemplateResult } from "lit";

const errorsBase = "https://errors.example.test/v1/";

/** Sample problems as a server would send them (sample data, not UI strings). */
export const SAMPLE_PROBLEMS: readonly Problem[] = [
  {
    type: `${errorsBase}not_found`,
    title: "Not found",
    status: 404,
    code: "not_found",
    detail: "The folder does not exist or you do not have access to it.",
    instance: "/api/v2/resources/0192f0c4-0000-7000-8000-000000000001",
    request_id: "0192f0c4-1a2b-7c3d-8e4f-000000000001",
    retryable: false,
  },
  {
    type: `${errorsBase}invalid_request`,
    title: "Invalid request",
    status: 400,
    code: "invalid_request",
    request_id: "0192f0c4-1a2b-7c3d-8e4f-000000000002",
    retryable: false,
    errors: [
      { pointer: "/name", code: "too_long", detail: "Name must be at most 255 characters." },
      { pointer: "/parent", code: "required", detail: "Choose a parent folder." },
    ],
  },
  {
    type: `${errorsBase}rate_limited`,
    title: "Rate limited",
    status: 429,
    code: "rate_limited",
    request_id: "0192f0c4-1a2b-7c3d-8e4f-000000000003",
    retryable: true,
    retry_after_ms: 2000,
  },
  {
    type: `${errorsBase}internal`,
    title: "Internal",
    status: 500,
    code: "internal",
    detail: "This detail must never be displayed.",
    request_id: "0192f0c4-1a2b-7c3d-8e4f-000000000004",
    retryable: true,
  },
  {
    type: `${errorsBase}outcome_unknown`,
    title: "Outcome unknown",
    status: 504,
    code: "outcome_unknown",
    request_id: "0192f0c4-1a2b-7c3d-8e4f-000000000005",
    retryable: true,
  },
  {
    type: `${errorsBase}app.photos.album_full`,
    title: "Album full",
    status: 409,
    code: "app.photos.album_full",
    detail: "The album already has 10,000 photos.",
    request_id: "0192f0c4-1a2b-7c3d-8e4f-000000000006",
    retryable: false,
  },
];

type Simulation = "malformed" | "html" | "network" | "rate_limited";

/** A fetch that imitates a misbehaving server. Used only by this page. */
function simulatedFetch(kind: Simulation): typeof fetch {
  let calls = 0;
  return (): Promise<Response> => {
    calls++;
    switch (kind) {
      case "malformed":
        return Promise.resolve(
          new Response('{"error":"NullPointerException at db.query()"}', {
            status: 500,
            headers: { "Content-Type": "application/problem+json", "X-Request-Id": "sim-malformed" },
          }),
        );
      case "html":
        return Promise.resolve(
          new Response("<html><body>502 Bad Gateway upstream=10.0.0.7:9000</body></html>", {
            status: 502,
            headers: { "Content-Type": "text/html" },
          }),
        );
      case "network":
        return Promise.reject(new TypeError("Failed to fetch"));
      case "rate_limited":
        if (calls === 1) {
          return Promise.resolve(
            new Response(
              JSON.stringify({ type: `${errorsBase}rate_limited`, title: "Rate limited", status: 429, code: "rate_limited", retryable: true, retry_after_ms: 300 }),
              { status: 429, headers: { "Content-Type": "application/problem+json", "Retry-After": "1" } },
            ),
          );
        }
        return Promise.resolve(new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }));
    }
  };
}

export class CsDevErrors extends LitElement {
  static override properties = {
    simulated: { state: true },
    simulatedOk: { state: true },
    busy: { state: true },
    dialogOpen: { state: true },
  };

  static override styles = css`
    :host {
      display: block;
    }
    h1 {
      font-size: var(--cs-font-size-xl);
      margin: 0 0 var(--cs-space-2);
    }
    h2 {
      font-size: var(--cs-font-size-lg);
      margin: var(--cs-space-6) 0 var(--cs-space-3);
    }
    .stack {
      display: grid;
      gap: var(--cs-space-3);
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: var(--cs-space-2);
      margin-bottom: var(--cs-space-3);
    }
    p {
      color: var(--cs-color-text-muted);
      margin: 0 0 var(--cs-space-3);
    }
    a {
      color: var(--cs-color-primary);
    }
    a:focus-visible {
      outline: var(--cs-focus-ring-width) solid var(--cs-color-focus-ring);
      outline-offset: var(--cs-focus-ring-offset);
    }
    .ok {
      padding: var(--cs-space-3);
      border-radius: var(--cs-radius-md);
      background: var(--cs-color-success-surface);
      color: var(--cs-color-success-text);
    }
  `;

  declare simulated: Problem | undefined;
  declare simulatedOk: string | undefined;
  declare busy: boolean;
  declare dialogOpen: boolean;

  constructor() {
    super();
    this.simulated = undefined;
    this.simulatedOk = undefined;
    this.busy = false;
    this.dialogOpen = false;
    new LocaleController(this);
  }

  override render(): TemplateResult {
    return html`
      <h1>${t("dev.heading")}</h1>
      <p>${t("dev.intro")}</p>
      <a href="#/">${t("dev.back_home")}</a>

      <h2>${t("dev.samples_heading")}</h2>
      <div class="stack">${SAMPLE_PROBLEMS.map((p) => html`<cs-error-banner .problem=${p}></cs-error-banner>`)}</div>

      <h2>${t("dev.pipeline_heading")}</h2>
      <p>${t("dev.pipeline_intro")}</p>
      <div class="row">
        ${(
          [
            ["malformed", "dev.sim_malformed"],
            ["html", "dev.sim_html"],
            ["network", "dev.sim_network"],
            ["rate_limited", "dev.sim_rate_limited"],
          ] as const
        ).map(
          ([kind, label]) =>
            html`<cs-button ?busy=${this.busy} @click=${() => void this.simulate(kind)}>${t(label)}</cs-button>`,
        )}
      </div>
      <div aria-live="polite">
        ${this.simulatedOk ? html`<div class="ok">${this.simulatedOk}</div>` : nothing}
      </div>
      <cs-error-banner dismissible .problem=${this.simulated}></cs-error-banner>

      <h2>${t("dev.components_heading")}</h2>
      <div class="stack">
        <cs-text-field
          label=${t("dev.field_label")}
          description=${t("dev.field_description")}
          error=${t("dev.field_error")}
          required
        ></cs-text-field>
        <div class="row">
          <cs-button variant="primary" @click=${this.openDialog}>${t("dev.open_dialog")}</cs-button>
          <cs-spinner></cs-spinner>
        </div>
      </div>
      <cs-dialog heading=${t("dev.dialog_heading")} ?open=${this.dialogOpen} @cs-close=${this.onDialogClose}>
        <p>${t("dev.dialog_body")}</p>
        <cs-button slot="footer" variant="primary" @click=${this.onDialogOk}>${t("dev.dialog_ok")}</cs-button>
      </cs-dialog>
    `;
  }

  private openDialog(): void {
    this.dialogOpen = true;
  }

  private onDialogClose(): void {
    this.dialogOpen = false;
  }

  private onDialogOk(): void {
    this.renderRoot.querySelector("cs-dialog")?.close();
  }

  private async simulate(kind: Simulation): Promise<void> {
    this.busy = true;
    this.simulated = undefined;
    this.simulatedOk = undefined;
    const client = new ApiClient({
      baseUrl: "https://simulated.invalid",
      fetch: simulatedFetch(kind),
      retryPolicy: new RetryPolicy({ maxAttempts: 2, initialDelayMs: 50, maxDelayMs: 2000 }),
    });
    try {
      const res = await client.get("/api/v2/simulated");
      this.simulatedOk = t("dev.sim_success", { attempts: res.attempts });
    } catch (e) {
      if (e instanceof ApiError) this.simulated = e.problem;
      else throw e;
    } finally {
      this.busy = false;
    }
  }
}

if (!customElements.get("cs-dev-errors")) customElements.define("cs-dev-errors", CsDevErrors);

declare global {
  interface HTMLElementTagNameMap {
    "cs-dev-errors": CsDevErrors;
  }
}
