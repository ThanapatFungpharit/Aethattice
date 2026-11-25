// Identity pages of the shell (contract M1 §7): sign-in, registration from a setup link, a minimal account page,
// the step-up password dialog and the single-active-tab notice. They use only the SDK's identity API.
import "@cs/components";
import { LocaleController } from "@cs/components";
import {
  ApiError,
  getMe,
  isApiError,
  isIdentityInputError,
  isMfaRequired,
  reauthenticate,
  register,
  signIn,
  signOut,
  synthesizeProblem,
  tenantFromGrant,
  t,
  type ApiClient,
  type AuthSession,
  type IdentityDeps,
  type IdentityInputField,
  type Me,
  type Problem,
} from "@cs/sdk";
import { LitElement, css, html, nothing, type TemplateResult } from "lit";

/** Who is signed in, as known to this tab (the login as entered, normalized by the server and WASM). */
export interface SignedInUser {
  readonly tenant: string;
  readonly login: string;
}

export type SignedInDetail = SignedInUser;

const pageStyles = css`
  :host {
    display: block;
  }
  h1 {
    font-size: var(--cs-font-size-xl);
    margin: 0 0 var(--cs-space-4);
  }
  form,
  .card {
    display: grid;
    gap: var(--cs-space-3);
    max-width: 28rem;
  }
  .actions {
    display: flex;
    gap: var(--cs-space-2);
  }
  .failure {
    margin: 0;
    padding: var(--cs-space-2) var(--cs-space-3);
    border-radius: var(--cs-radius-md);
    color: var(--cs-color-danger-text);
    background: var(--cs-color-danger-surface);
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--cs-space-2) var(--cs-space-4);
    margin: 0;
  }
  dt {
    font-weight: var(--cs-font-weight-bold);
  }
  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }
`;

/** Outcome of a failed identity call, split into what the form shows where. */
interface Failure {
  /** Field to mark invalid. */
  readonly field?: IdentityInputField;
  /** Inline message (wrong credentials, MFA) shown in a live region. */
  readonly message?: string;
  /** Everything else goes to cs-error-banner. */
  readonly problem?: Problem;
}

function classify(e: unknown): Failure {
  if (isIdentityInputError(e)) return { field: e.field };
  if (isMfaRequired(e)) return { message: t("auth.mfa_unavailable") };
  // §6: wrong password, unknown account, unknown tenant and disabled user all look the same.
  if (isApiError(e) && e.problem.code === "unauthenticated") return { message: t("auth.signin_failed") };
  if (isApiError(e)) return { problem: e.problem };
  return { problem: synthesizeProblem("internal") };
}

function fieldError(f: Failure | undefined, field: IdentityInputField): string | undefined {
  return f?.field === field ? t(`auth.invalid_${field}`) : undefined;
}

function renderFailure(f: Failure | undefined): TemplateResult {
  return html`<div aria-live="polite">${f?.message ? html`<p class="failure" role="alert">${f.message}</p>` : nothing}</div>
    ${f?.problem ? html`<cs-error-banner .problem=${f.problem}></cs-error-banner>` : nothing}`;
}

function value(root: ShadowRoot | HTMLElement, name: string): string {
  return root.querySelector<HTMLElement & { value: string }>(`cs-text-field[name="${name}"]`)?.value ?? "";
}

function signedInEvent(user: SignedInUser): CustomEvent<SignedInDetail> {
  return new CustomEvent<SignedInDetail>("cs-signed-in", { detail: user, bubbles: true, composed: true });
}

// ---- sign-in ----

export class CsSignInPage extends LitElement {
  static override properties = {
    identity: { attribute: false },
    tenant: { type: String },
    busy: { state: true },
    failure: { state: true },
  };
  static override styles = pageStyles;

  declare identity: IdentityDeps | undefined;
  declare tenant: string;
  declare busy: boolean;
  declare failure: Failure | undefined;

  constructor() {
    super();
    this.identity = undefined;
    this.tenant = "";
    this.busy = false;
    this.failure = undefined;
    new LocaleController(this);
  }

  override render(): TemplateResult {
    const f = this.failure;
    return html`<h1>${t("auth.signin_heading")}</h1>
      <form novalidate @submit=${this.onSubmit}>
        <cs-text-field name="tenant" label=${t("auth.tenant")} description=${t("auth.tenant_description")} required
          .value=${this.tenant} .error=${fieldError(f, "tenant")}></cs-text-field>
        <cs-text-field name="login" label=${t("auth.login")} autocomplete="username" required .error=${fieldError(f, "login")}></cs-text-field>
        <cs-text-field name="password" type="password" label=${t("auth.password")} autocomplete="current-password" required
          .error=${fieldError(f, "password")}></cs-text-field>
        ${renderFailure(f)}
        <div class="actions"><cs-button variant="primary" type="submit" ?busy=${this.busy}>${t("auth.signin_submit")}</cs-button></div>
      </form>`;
  }

  /** Submits the form (also used by tests). Resolves when the attempt has finished. */
  async submit(): Promise<void> {
    const identity = this.identity;
    if (!identity || this.busy) return;
    const root = this.renderRoot as ShadowRoot;
    const tenant = value(root, "tenant").trim().toLowerCase();
    const login = value(root, "login");
    const password = value(root, "password");
    this.busy = true;
    this.failure = undefined;
    try {
      await signIn(identity, tenant, login, password);
      this.clearPassword();
      this.dispatchEvent(signedInEvent({ tenant, login: await identity.engine.normalizeLogin(login) }));
    } catch (e) {
      this.failure = classify(e);
      this.clearPassword();
    } finally {
      this.busy = false;
    }
  }

  private clearPassword(): void {
    const pw = this.renderRoot.querySelector<HTMLElement & { value: string }>('cs-text-field[name="password"]');
    if (pw) pw.value = "";
  }

  private onSubmit(e: Event): void {
    e.preventDefault();
    void this.submit();
  }
}

// ---- registration from a setup link ----

export class CsRegisterPage extends LitElement {
  static override properties = {
    identity: { attribute: false },
    token: { type: String },
    busy: { state: true },
    failure: { state: true },
    mismatch: { state: true },
  };
  static override styles = pageStyles;

  declare identity: IdentityDeps | undefined;
  declare token: string;
  declare busy: boolean;
  declare failure: Failure | undefined;
  declare mismatch: boolean;

  constructor() {
    super();
    this.identity = undefined;
    this.token = "";
    this.busy = false;
    this.failure = undefined;
    this.mismatch = false;
    new LocaleController(this);
  }

  override render(): TemplateResult {
    const f = this.failure;
    return html`<h1>${t("auth.register_heading")}</h1>
      <p>${t("auth.register_intro")}</p>
      <form novalidate @submit=${this.onSubmit}>
        <cs-text-field name="setup_link" label=${t("auth.setup_link")} required .value=${this.token}
          .error=${fieldError(f, "setup_link")}></cs-text-field>
        <cs-text-field name="login" label=${t("auth.login")} autocomplete="username" required .error=${fieldError(f, "login")}></cs-text-field>
        <cs-text-field name="password" type="password" label=${t("auth.new_password")} autocomplete="new-password" required
          .error=${fieldError(f, "password")}></cs-text-field>
        <cs-text-field name="confirm" type="password" label=${t("auth.confirm_password")} autocomplete="new-password" required
          .error=${this.mismatch ? t("auth.password_mismatch") : undefined}></cs-text-field>
        ${renderFailure(f)}
        <div class="actions"><cs-button variant="primary" type="submit" ?busy=${this.busy}>${t("auth.register_submit")}</cs-button></div>
      </form>`;
  }

  async submit(): Promise<void> {
    const identity = this.identity;
    if (!identity || this.busy) return;
    const root = this.renderRoot as ShadowRoot;
    const token = value(root, "setup_link");
    const login = value(root, "login");
    const password = value(root, "password");
    this.failure = undefined;
    this.mismatch = password !== value(root, "confirm");
    if (this.mismatch) return;
    this.busy = true;
    try {
      await register(identity, token, login, password);
      const r = identity.session.state;
      if (r.authenticated) {
        this.dispatchEvent(signedInEvent({ tenant: tenantFromGrant(token.trim()), login: await identity.engine.normalizeLogin(login) }));
      }
    } catch (e) {
      this.failure = classify(e);
    } finally {
      this.busy = false;
    }
  }

  private onSubmit(e: Event): void {
    e.preventDefault();
    void this.submit();
  }
}

// ---- account ----

/** The account page: who is signed in, from `GET /api/v2/me` (rev 7), and sign-out. */
export class CsAccountPage extends LitElement {
  static override properties = {
    user: { attribute: false },
    session: { attribute: false },
    authedClient: { attribute: false },
    busy: { state: true },
    problem: { state: true },
    me: { state: true },
  };
  static override styles = pageStyles;

  declare user: SignedInUser | undefined;
  declare session: AuthSession | undefined;
  declare authedClient: ApiClient | undefined;
  declare busy: boolean;
  declare problem: Problem | undefined;
  declare me: Me | undefined;

  private loading: Promise<void> | undefined;

  constructor() {
    super();
    this.user = undefined;
    this.session = undefined;
    this.authedClient = undefined;
    this.busy = false;
    this.problem = undefined;
    this.me = undefined;
    new LocaleController(this);
  }

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  /** Loads `GET /api/v2/me`. Until it answers, the page shows what this tab knows from sign-in. */
  load(): Promise<void> {
    const client = this.authedClient;
    if (!client) return Promise.resolve();
    this.loading ??= getMe(client)
      .then((me) => {
        this.me = me;
      })
      .catch((e: unknown) => {
        this.problem = isApiError(e) ? e.problem : synthesizeProblem("internal");
      })
      .finally(() => {
        this.loading = undefined;
      });
    return this.loading;
  }

  override render(): TemplateResult {
    const u = this.user;
    const me = this.me;
    return html`<h1>${t("auth.account_heading")}</h1>
      <section class="card" aria-labelledby="who" aria-busy=${this.loading !== undefined && me === undefined ? "true" : "false"}>
        <h2 id="who">${t("auth.signed_in_as")}</h2>
        <dl>
          ${me && me.display_name.length > 0 ? html`<dt>${t("auth.display_name")}</dt><dd class="display-name">${me.display_name}</dd>` : nothing}
          <dt>${t("auth.login")}</dt>
          <dd class="login">${me?.login ?? u?.login ?? ""}</dd>
          <dt>${t("auth.tenant")}</dt>
          <dd class="tenant">${me?.tenant_id ?? u?.tenant ?? ""}</dd>
          <dt>${t("auth.session")}</dt>
          <dd class="session">${me?.sid ?? this.session?.state.sessionId ?? ""}</dd>
          ${me
            ? html`<dt>${t("auth.signed_in_at")}</dt>
                <dd class="auth-time"><time datetime=${new Date(me.auth_time * 1000).toISOString()}>${new Date(me.auth_time * 1000).toLocaleString()}</time></dd>
                <dt>${t("auth.methods")}</dt>
                <dd class="amr">${me.amr.join(", ")}</dd>`
            : nothing}
        </dl>
        ${this.problem ? html`<cs-error-banner .problem=${this.problem}></cs-error-banner>` : nothing}
        <div class="actions">
          <cs-button class="sign-out" ?busy=${this.busy} @click=${() => void this.signOut()}>${t("auth.sign_out")}</cs-button>
        </div>
      </section>`;
  }

  async signOut(): Promise<void> {
    const client = this.authedClient;
    const session = this.session;
    if (!client || !session || this.busy) return;
    this.busy = true;
    this.problem = undefined;
    try {
      await signOut(client, session);
      this.dispatchEvent(new CustomEvent("cs-signed-out", { bubbles: true, composed: true }));
    } catch (e) {
      this.problem = e instanceof ApiError ? e.problem : synthesizeProblem("internal");
    } finally {
      this.busy = false;
    }
  }
}

// ---- step-up ----

/**
 * Password re-entry for `StepUpRequired` (§2.3 [R2]). Runs `opaque/reauth/{start,finish}` (rev 7) on the current
 * session, so no new session is created, and fires `cs-step-up-done` on success; closing fires `cs-step-up-cancel`.
 */
export class CsStepUpDialog extends LitElement {
  static override properties = {
    open: { type: Boolean },
    user: { attribute: false },
    identity: { attribute: false },
    authedClient: { attribute: false },
    busy: { state: true },
    failure: { state: true },
  };
  static override styles = pageStyles;

  declare authedClient: ApiClient | undefined;
  declare open: boolean;
  declare user: SignedInUser | undefined;
  declare identity: IdentityDeps | undefined;
  declare busy: boolean;
  declare failure: Failure | undefined;

  constructor() {
    super();
    this.open = false;
    this.user = undefined;
    this.identity = undefined;
    this.authedClient = undefined;
    this.busy = false;
    this.failure = undefined;
    new LocaleController(this);
  }

  override render(): TemplateResult {
    const f = this.failure;
    return html`<cs-dialog heading=${t("auth.step_up_heading")} ?open=${this.open} @cs-close=${this.onClose}>
      <form novalidate @submit=${this.onSubmit}>
        <p>${t("auth.step_up_intro")}</p>
        <cs-text-field name="password" type="password" label=${t("auth.password")} autocomplete="current-password" required
          .error=${fieldError(f, "password")}></cs-text-field>
        ${renderFailure(f)}
        <div class="actions">
          <cs-button variant="primary" type="submit" ?busy=${this.busy}>${t("auth.step_up_submit")}</cs-button>
        </div>
      </form>
    </cs-dialog>`;
  }

  async submit(): Promise<void> {
    const identity = this.identity;
    const user = this.user;
    const client = this.authedClient;
    if (!identity || !user || !client || this.busy) return;
    const field = this.renderRoot.querySelector<HTMLElement & { value: string }>('cs-text-field[name="password"]');
    const password = field?.value ?? "";
    this.busy = true;
    this.failure = undefined;
    try {
      await reauthenticate(identity, client, user.tenant, user.login, password);
      if (field) field.value = "";
      this.open = false;
      this.dispatchEvent(new CustomEvent("cs-step-up-done", { bubbles: true, composed: true }));
    } catch (e) {
      if (field) field.value = "";
      this.failure = classify(e);
    } finally {
      this.busy = false;
    }
  }

  private onSubmit(e: Event): void {
    e.preventDefault();
    void this.submit();
  }

  private onClose(): void {
    if (!this.open) return;
    this.open = false;
    this.failure = undefined;
    this.dispatchEvent(new CustomEvent("cs-step-up-cancel", { bubbles: true, composed: true }));
  }
}

for (const [name, ctor] of [
  ["cs-sign-in-page", CsSignInPage],
  ["cs-register-page", CsRegisterPage],
  ["cs-account-page", CsAccountPage],
  ["cs-step-up-dialog", CsStepUpDialog],
] as const) {
  if (!customElements.get(name)) customElements.define(name, ctor);
}

declare global {
  interface HTMLElementTagNameMap {
    "cs-sign-in-page": CsSignInPage;
    "cs-register-page": CsRegisterPage;
    "cs-account-page": CsAccountPage;
    "cs-step-up-dialog": CsStepUpDialog;
  }
}
