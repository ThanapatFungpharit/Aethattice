// Web shell skeleton (spec §14.1): header with global navigation and launcher placeholder, notification
// region and main region. M0 renders service readiness from GET /readyz through the error model.
import "@cs/components";
import { LocaleController } from "@cs/components";
import { t, type ApiClient } from "@cs/sdk";
import { LitElement, css, html, nothing, type TemplateResult } from "lit";
import "./dev-errors";
import { checkReadiness, type Readiness } from "./readiness";

type Route = "home" | "dev-errors";

function routeFromHash(hash: string): Route {
  return hash === "#/dev/errors" ? "dev-errors" : "home";
}

export class CsShellApp extends LitElement {
  static override properties = {
    client: { attribute: false },
    showDevLink: { type: Boolean, attribute: "show-dev-link" },
    readiness: { state: true },
    route: { state: true },
    launcherOpen: { state: true },
  };

  static override styles = css`
    :host {
      display: flex;
      flex-direction: column;
      min-height: 100vh;
      background: var(--cs-color-bg);
      color: var(--cs-color-text);
      font-family: var(--cs-font-family);
      line-height: var(--cs-line-height-normal);
    }
    .skip-link {
      position: absolute;
      left: var(--cs-space-2);
      top: -10rem;
      padding: var(--cs-space-2) var(--cs-space-3);
      background: var(--cs-color-bg);
      color: var(--cs-color-primary);
      border-radius: var(--cs-radius-sm);
      z-index: 10;
    }
    .skip-link:focus {
      top: var(--cs-space-2);
    }
    :focus-visible {
      outline: var(--cs-focus-ring-width) solid var(--cs-color-focus-ring);
      outline-offset: var(--cs-focus-ring-offset);
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: var(--cs-space-4);
      padding: var(--cs-space-2) var(--cs-space-4);
      background: var(--cs-color-surface);
      border-bottom: 1px solid var(--cs-color-border);
    }
    .brand {
      font-weight: var(--cs-font-weight-bold);
      font-size: var(--cs-font-size-lg);
    }
    nav ul {
      display: flex;
      align-items: center;
      gap: var(--cs-space-2);
      list-style: none;
      margin: 0;
      padding: 0;
    }
    nav a {
      color: var(--cs-color-primary);
    }
    .notifications {
      padding: var(--cs-space-2) var(--cs-space-4);
      border-bottom: 1px solid var(--cs-color-border);
      color: var(--cs-color-text-muted);
      font-size: var(--cs-font-size-sm);
    }
    .notifications h2 {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip-path: inset(50%);
      white-space: nowrap;
    }
    main {
      flex: 1;
      box-sizing: border-box;
      width: 100%;
      max-width: var(--cs-content-max-width);
      margin: 0 auto;
      padding: var(--cs-space-5) var(--cs-space-4);
    }
    main:focus {
      outline: none;
    }
    h1 {
      font-size: var(--cs-font-size-xl);
      margin: 0 0 var(--cs-space-4);
    }
    .card {
      display: grid;
      gap: var(--cs-space-3);
      padding: var(--cs-space-4);
      border: 1px solid var(--cs-color-border);
      border-radius: var(--cs-radius-lg);
      background: var(--cs-color-surface);
    }
    .card h2 {
      font-size: var(--cs-font-size-lg);
      margin: 0;
    }
    .ready {
      color: var(--cs-color-success-text);
      background: var(--cs-color-success-surface);
      padding: var(--cs-space-2) var(--cs-space-3);
      border-radius: var(--cs-radius-md);
      margin: 0;
    }
    .actions {
      display: flex;
      gap: var(--cs-space-2);
    }
  `;

  declare client: ApiClient | undefined;
  declare showDevLink: boolean;
  declare readiness: Readiness | "checking";
  declare route: Route;
  declare launcherOpen: boolean;

  private abort: AbortController | undefined;
  private readonly onHashChange = (): void => {
    this.route = routeFromHash(location.hash);
  };

  constructor() {
    super();
    this.client = undefined;
    this.showDevLink = false;
    this.readiness = "checking";
    this.route = "home";
    this.launcherOpen = false;
    new LocaleController(this);
  }

  override connectedCallback(): void {
    super.connectedCallback();
    window.addEventListener("hashchange", this.onHashChange);
    this.route = routeFromHash(location.hash);
    void this.refreshReadiness();
  }

  override disconnectedCallback(): void {
    window.removeEventListener("hashchange", this.onHashChange);
    this.abort?.abort();
    super.disconnectedCallback();
  }

  /** Re-checks GET /readyz. Resolves when the status has been rendered. */
  async refreshReadiness(): Promise<void> {
    const client = this.client;
    if (!client) return;
    this.abort?.abort();
    const ctl = new AbortController();
    this.abort = ctl;
    this.readiness = "checking";
    try {
      const r = await checkReadiness(client, ctl.signal);
      if (!ctl.signal.aborted) this.readiness = r;
    } catch {
      // Aborted because a newer check started or the shell was removed.
    }
    await this.updateComplete;
  }

  override render(): TemplateResult {
    return html`
      <a class="skip-link" href="#main" @click=${this.skipToMain}>${t("shell.skip_to_main")}</a>
      <header>
        <span class="brand">${t("shell.product_name")}</span>
        <nav aria-label=${t("shell.global_nav")}>
          <ul>
            <li>
              <cs-button variant="ghost" class="launcher" aria-haspopup="dialog" @click=${this.openLauncher}
                >${t("shell.launcher")}</cs-button
              >
            </li>
            ${this.showDevLink ? html`<li><a href="#/dev/errors">${t("shell.dev_link")}</a></li>` : nothing}
          </ul>
        </nav>
      </header>
      <section class="notifications" aria-labelledby="notifications-heading">
        <h2 id="notifications-heading">${t("shell.notifications")}</h2>
        <div role="log" aria-live="polite">${t("shell.notifications_empty")}</div>
      </section>
      <main id="main" tabindex="-1">${this.route === "dev-errors" ? html`<cs-dev-errors></cs-dev-errors>` : this.renderHome()}</main>
      <cs-dialog heading=${t("shell.launcher_heading")} ?open=${this.launcherOpen} @cs-close=${this.onLauncherClose}>
        <p>${t("shell.launcher_placeholder")}</p>
      </cs-dialog>
    `;
  }

  private renderHome(): TemplateResult {
    const r = this.readiness;
    let status: TemplateResult;
    if (r === "checking") status = html`<cs-spinner label=${t("shell.status_checking")}></cs-spinner>`;
    else if (r.state === "ready") status = html`<p class="ready" role="status">${t("shell.status_ready")}</p>`;
    else
      status = html`<p>${t("shell.status_not_ready")}</p>
        <cs-error-banner .problem=${r.problem}></cs-error-banner>`;
    return html`<h1>${t("shell.home_heading")}</h1>
      <section class="card" aria-labelledby="status-heading">
        <h2 id="status-heading">${t("shell.status_heading")}</h2>
        <div class="status">${status}</div>
        <div class="actions">
          <cs-button class="recheck" ?busy=${r === "checking"} @click=${() => void this.refreshReadiness()}
            >${t("shell.status_recheck")}</cs-button
          >
        </div>
      </section>`;
  }

  private skipToMain(e: Event): void {
    e.preventDefault();
    this.renderRoot.querySelector<HTMLElement>("main")?.focus();
  }

  private openLauncher(): void {
    this.launcherOpen = true;
  }

  private onLauncherClose(): void {
    this.launcherOpen = false;
  }
}

if (!customElements.get("cs-shell-app")) customElements.define("cs-shell-app", CsShellApp);

declare global {
  interface HTMLElementTagNameMap {
    "cs-shell-app": CsShellApp;
  }
}
