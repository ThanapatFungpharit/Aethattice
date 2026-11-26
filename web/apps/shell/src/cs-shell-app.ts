// Web shell skeleton (spec §14.1): header with global navigation and launcher placeholder, notification
// region and main region. M0 renders service readiness from GET /readyz through the error model.
import "@cs/components";
import { LocaleController } from "@cs/components";
import { MFA_ENROLMENT_SCOPE, isStepUpRequired, t, type ApiClient, type CredentialsLike, type IdentityDeps, type ReregisterOutcome } from "@cs/sdk";
import { LitElement, css, html, nothing, type TemplateResult } from "lit";
import "./auth-pages";
import type { SignedInUser } from "./auth-pages";
import "./dev-errors";
import "./security-pages";
import { checkReadiness, type Readiness } from "./readiness";

type Route = "home" | "dev-errors" | "sign-in" | "register" | "account" | "security" | "recover" | "enrol";

const REGISTER_PREFIX = "#/register/";
const RECOVER_PREFIX = "#/recover/";

export function routeFromHash(hash: string): Route {
  if (hash === "#/dev/errors") return "dev-errors";
  if (hash === "#/sign-in") return "sign-in";
  if (hash === "#/register" || hash.startsWith(REGISTER_PREFIX)) return "register";
  if (hash === "#/account") return "account";
  if (hash === "#/security") return "security";
  if (hash === "#/recover" || hash.startsWith(RECOVER_PREFIX)) return "recover";
  if (hash === "#/enrol") return "enrol";
  return "home";
}

export class CsShellApp extends LitElement {
  static override properties = {
    client: { attribute: false },
    showDevLink: { type: Boolean, attribute: "show-dev-link" },
    readiness: { state: true },
    route: { state: true },
    launcherOpen: { state: true },
    identity: { attribute: false },
    authedClient: { attribute: false },
    user: { state: true },
    stepUpOpen: { state: true },
    setupToken: { state: true },
    recoveryToken: { state: true },
    credentials: { attribute: false },
    notice: { state: true },
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
    .tab-notice {
      margin: 0;
      padding: var(--cs-space-2) var(--cs-space-4);
      background: var(--cs-color-surface-raised);
      border-bottom: 1px solid var(--cs-color-border-strong);
    }
  `;

  declare client: ApiClient | undefined;
  declare showDevLink: boolean;
  declare readiness: Readiness | "checking";
  declare route: Route;
  declare launcherOpen: boolean;
  /** OPAQUE engine, auth client and session (contract M1 §7). Without it the identity pages are not offered. */
  declare identity: IdentityDeps | undefined;
  /** Client whose auth hook is `identity.session`, for authenticated calls such as logout. */
  declare authedClient: ApiClient | undefined;
  declare user: SignedInUser | undefined;
  declare stepUpOpen: boolean;
  declare setupToken: string;
  /** Token of an emailed recovery link (rev 10), taken from `#/recover/<token>` and removed from the address bar. */
  declare recoveryToken: string;
  /** `navigator.credentials` when WebAuthn is available; passkey options are hidden without it. */
  declare credentials: CredentialsLike | undefined;
  /** Non-blocking notice in the notifications region (e.g. a failed transparent re-registration, rev 9). */
  declare notice: string | undefined;

  private abort: AbortController | undefined;
  private unsubscribeSession: (() => void) | undefined;
  private stepUpWaiters: { resolve: (ok: boolean) => void }[] = [];
  private readonly onHashChange = (): void => {
    this.applyHash();
  };

  constructor() {
    super();
    this.client = undefined;
    this.showDevLink = false;
    this.readiness = "checking";
    this.route = "home";
    this.launcherOpen = false;
    this.identity = undefined;
    this.authedClient = undefined;
    this.user = undefined;
    this.stepUpOpen = false;
    this.setupToken = "";
    this.recoveryToken = "";
    this.credentials = undefined;
    this.notice = undefined;
    new LocaleController(this);
  }

  override connectedCallback(): void {
    super.connectedCallback();
    window.addEventListener("hashchange", this.onHashChange);
    this.applyHash();
    this.unsubscribeSession = this.identity?.session.subscribe((s) => {
      // Signed out here or in another tab (or the refresh cookie was rejected).
      // Rev 8: a session that ended (revoked, reuse, refresh refused) goes back to sign-in.
      if (!s.authenticated && this.user !== undefined) {
        this.user = undefined;
        if (this.route === "account" || this.route === "security" || this.route === "enrol") this.navigate("#/sign-in");
      }
      this.requestUpdate();
    });
    void this.refreshReadiness();
  }

  override disconnectedCallback(): void {
    window.removeEventListener("hashchange", this.onHashChange);
    this.unsubscribeSession?.();
    this.abort?.abort();
    super.disconnectedCallback();
  }

  /**
   * Runs `op`; when it fails with StepUpRequired (§2.3 [R2]) asks for the password again and, after a successful
   * re-authentication, retries `op` once. Rejects with the original StepUpRequired when the user cancels.
   */
  async runWithStepUp<T>(op: () => Promise<T>): Promise<T> {
    try {
      return await op();
    } catch (e) {
      if (!isStepUpRequired(e) || !this.user || !this.identity) throw e;
      const ok = await new Promise<boolean>((resolve) => {
        this.stepUpWaiters.push({ resolve });
        this.stepUpOpen = true;
      });
      if (!ok) throw e;
      return op();
    }
  }

  private settleStepUp(ok: boolean): void {
    this.stepUpOpen = false;
    const waiters = this.stepUpWaiters;
    this.stepUpWaiters = [];
    for (const w of waiters) w.resolve(ok);
  }

  private applyHash(): void {
    const hash = location.hash;
    this.route = routeFromHash(hash);
    if (hash.startsWith(REGISTER_PREFIX)) {
      // The setup link is a bearer secret: take it out of the address bar and history.
      this.setupToken = decodeURIComponent(hash.slice(REGISTER_PREFIX.length));
      history.replaceState(null, "", "#/register");
    }
    if (hash.startsWith(RECOVER_PREFIX)) {
      // The recovery link is a bearer secret as well.
      this.recoveryToken = decodeURIComponent(hash.slice(RECOVER_PREFIX.length));
      history.replaceState(null, "", "#/recover");
    }
  }

  private navigate(hash: string): void {
    if (location.hash !== hash) location.hash = hash;
    this.route = routeFromHash(hash);
  }

  private onSignedIn(e: CustomEvent<SignedInUser>): void {
    this.user = e.detail;
    this.setupToken = "";
    this.recoveryToken = "";
    // Rev 11: an enrolment-only session (scope read for routing only, never trusted) goes to forced enrolment.
    this.navigate(this.identity?.session.scope === MFA_ENROLMENT_SCOPE ? "#/enrol" : "#/account");
  }

  /**
   * Identity deps for the sign-in flows: the authenticated client for the rev 9 transparent re-registration, and a
   * listener that shows a non-blocking notice when it fails (it is retried at the next sign-in).
   */
  get signInDeps(): IdentityDeps | undefined {
    const id = this.identity;
    if (!id) return undefined;
    return {
      ...id,
      ...(this.authedClient !== undefined && { authedClient: this.authedClient }),
      onReregister: (o: ReregisterOutcome) => {
        this.notice = o.ok ? undefined : t("auth.reregister_failed");
      },
    };
  }

  private readonly stepUpRunner = <T,>(op: () => Promise<T>): Promise<T> => this.runWithStepUp(op);

  private onSignedOut(): void {
    this.user = undefined;
    this.navigate("#/sign-in");
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
            ${this.identity
              ? this.signedIn
                ? html`<li><a href="#/account">${t("auth.account_link")}</a></li>
                    <li><a href="#/security">${t("security.link")}</a></li>`
                : html`<li><a href="#/sign-in">${t("auth.signin_link")}</a></li>`
              : nothing}
            ${this.showDevLink ? html`<li><a href="#/dev/errors">${t("shell.dev_link")}</a></li>` : nothing}
          </ul>
        </nav>
      </header>
      ${this.renderTabNotice()}
      <section class="notifications" aria-labelledby="notifications-heading">
        <h2 id="notifications-heading">${t("shell.notifications")}</h2>
        <div role="log" aria-live="polite">
          ${this.notice
            ? html`<p class="notice">${this.notice}</p>
                <cs-button variant="ghost" class="dismiss-notice" @click=${() => {
                  this.notice = undefined;
                }}>${t("shell.dismiss")}</cs-button>`
            : t("shell.notifications_empty")}
        </div>
      </section>
      <main id="main" tabindex="-1">${this.renderRoute()}</main>
      <cs-dialog heading=${t("shell.launcher_heading")} ?open=${this.launcherOpen} @cs-close=${this.onLauncherClose}>
        <p>${t("shell.launcher_placeholder")}</p>
      </cs-dialog>
      ${this.identity
        ? html`<cs-step-up-dialog
            ?open=${this.stepUpOpen}
            .user=${this.user}
            .identity=${this.identity}
            .authedClient=${this.authedClient}
            .credentials=${this.credentials}
            @cs-step-up-done=${() => {
              this.settleStepUp(true);
            }}
            @cs-step-up-cancel=${() => {
              this.settleStepUp(false);
            }}
          ></cs-step-up-dialog>`
        : nothing}
    `;
  }

  private get signedIn(): boolean {
    return this.user !== undefined && this.identity?.session.state.authenticated === true;
  }

  /**
   * Contract M1 §3 [R1]: without Web Locks the SDK serializes refreshes with a localStorage lease (or not at all),
   * and the UI degrades to a single active tab, so the user is told to keep one tab open.
   */
  private renderTabNotice(): TemplateResult | typeof nothing {
    const mode = this.identity?.session.crossTabMode;
    if (!this.signedIn || mode === undefined || mode === "web-locks") return nothing;
    return html`<p class="tab-notice" role="status">${t("auth.single_tab_notice")}</p>`;
  }

  private renderRoute(): TemplateResult {
    const id = this.identity;
    switch (this.route) {
      case "dev-errors":
        return html`<cs-dev-errors></cs-dev-errors>`;
      case "sign-in":
        if (id) return this.renderSignIn();
        break;
      case "recover":
        if (id)
          return html`<cs-recovery-page .identity=${this.signInDeps} .token=${this.recoveryToken} @cs-signed-in=${this.onSignedIn}></cs-recovery-page>`;
        break;
      case "security":
        if (id && this.signedIn)
          return html`<cs-security-page .user=${this.user} .identity=${id} .authedClient=${this.authedClient} .credentials=${this.credentials}
            .runWithStepUp=${this.stepUpRunner} @cs-signed-out=${this.onSignedOut}></cs-security-page>`;
        if (id) return this.renderSignIn();
        break;
      case "enrol":
        if (id && this.signedIn)
          return html`<cs-enrolment-page .session=${id.session} .authedClient=${this.authedClient} .credentials=${this.credentials}
            .runWithStepUp=${this.stepUpRunner} @cs-signed-out=${this.onSignedOut}></cs-enrolment-page>`;
        if (id) return this.renderSignIn();
        break;
      case "register":
        if (id)
          return html`<cs-register-page .identity=${id} .token=${this.setupToken} @cs-signed-in=${this.onSignedIn}></cs-register-page>`;
        break;
      case "account":
        if (id && this.signedIn)
          return html`<cs-account-page .user=${this.user} .session=${id.session} .authedClient=${this.authedClient}
            @cs-signed-out=${this.onSignedOut}></cs-account-page>`;
        if (id) return this.renderSignIn();
        break;
      case "home":
        break;
    }
    return this.renderHome();
  }

  private renderSignIn(): TemplateResult {
    return html`<cs-sign-in-page .identity=${this.signInDeps} .credentials=${this.credentials} @cs-signed-in=${this.onSignedIn}></cs-sign-in-page>`;
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
