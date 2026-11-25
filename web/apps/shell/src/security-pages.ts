// Security, recovery and MFA-enrolment pages of the shell (contract M1 §7, §2.2, §2.3, §3, §4, rev 9–11).
// They use only the SDK's identity, WebAuthn and account APIs; sensitive operations go through `runWithStepUp`,
// which opens the step-up dialog (password or passkey) on StepUpRequired and retries once.
import "@cs/components";
import { LocaleController } from "@cs/components";
import {
  RecoveryFlow,
  approveRecoveryRequest,
  cancelRecoveryRequest,
  changePassword,
  deletePasskey,
  generateRecoveryCodes,
  isCanonicalTenantId,
  isStepUpRequired,
  listPasskeys,
  listRecoveryRequests,
  listSessions,
  registerPasskey,
  remainingRecoveryCodes,
  revokeSession,
  signOut,
  t,
  type ApiClient,
  type AuthSession,
  type CredentialsLike,
  type IdentityDeps,
  type Passkey,
  type RecoveryRequestInfo,
  type SessionInfo,
} from "@cs/sdk";
import { LitElement, css, html, nothing, type TemplateResult } from "lit";
import { classify, fieldError, pageStyles, renderFailure, signedInEvent, value, type Failure, type SignedInUser } from "./auth-pages";

/** Runs an operation; on StepUpRequired asks the user to confirm it's them and retries once (shell-provided). */
export type StepUpRunner = <T>(op: () => Promise<T>) => Promise<T>;

const direct: StepUpRunner = (op) => op();

/** Failure of a security action: a cancelled step-up gets its own message; the rest as on the identity forms. */
function securityFailure(e: unknown): Failure {
  if (isStepUpRequired(e)) return { message: t("security.step_up_cancelled") };
  return classify(e, t("security.action_unauthenticated"));
}

function when(iso: string | null): TemplateResult {
  if (iso === null) return html`${t("security.never")}`;
  return html`<time datetime=${iso}>${new Date(iso).toLocaleString()}</time>`;
}

const securityStyles = [
  pageStyles,
  css`
    section {
      display: grid;
      gap: var(--cs-space-3);
      margin-block-end: var(--cs-space-5);
      max-width: 40rem;
    }
    h2 {
      font-size: var(--cs-font-size-lg);
      margin: 0;
    }
    ul.items {
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: var(--cs-space-2);
    }
    ul.items > li {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: var(--cs-space-2);
      padding: var(--cs-space-3);
      border: 1px solid var(--cs-color-border);
      border-radius: var(--cs-radius-md);
    }
    .meta {
      color: var(--cs-color-text-muted);
      font-size: var(--cs-font-size-sm);
    }
    .badge {
      font-weight: var(--cs-font-weight-bold);
    }
    .status {
      margin: 0;
    }
    ol.codes {
      font-family: ui-monospace, monospace;
      margin: 0;
    }
  `,
];

/** Recovery codes shown once (rev 10/11), with copy and download. */
function renderCodes(codes: readonly string[], copied: boolean, onCopy: () => void, onDone: () => void): TemplateResult {
  return html`<div class="card codes-once" role="region" aria-labelledby="codes-heading">
    <h3 id="codes-heading">${t("security.codes_heading")}</h3>
    <p>${t("security.codes_once")}</p>
    <ol class="codes">${codes.map((c) => html`<li>${c}</li>`)}</ol>
    <div class="actions">
      <cs-button class="codes-copy" @click=${onCopy}>${t("security.codes_copy")}</cs-button>
      <cs-button class="codes-download" @click=${() => {
        downloadCodes(codes);
      }}>${t("security.codes_download")}</cs-button>
      <cs-button variant="primary" class="codes-done" @click=${onDone}>${t("security.codes_done")}</cs-button>
    </div>
    <p class="status" role="status">${copied ? t("security.codes_copied") : nothing}</p>
  </div>`;
}

async function copyCodes(codes: readonly string[]): Promise<boolean> {
  const clipboard = (navigator as { clipboard?: Partial<Clipboard> }).clipboard;
  if (typeof clipboard?.writeText !== "function") return false;
  try {
    await clipboard.writeText(codes.join("\n"));
    return true;
  } catch {
    return false;
  }
}

function downloadCodes(codes: readonly string[]): void {
  const blob = new Blob([`${t("security.codes_file_header")}\n\n${codes.join("\n")}\n`], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "recovery-codes.txt";
  a.click();
  URL.revokeObjectURL(url);
}

// ---- security page ----

type SectionKey = "password" | "sessions" | "passkeys" | "codes" | "requests";

/**
 * The security page (§7): password change (rev 9 `password_change`, other sessions signed out), own sessions with
 * revoke (current marked), passkeys (list, add, remove), recovery codes (generate, shown once) and pending recovery
 * requests (approve, cancel; rev 10).
 */
export class CsSecurityPage extends LitElement {
  static override properties = {
    user: { attribute: false },
    identity: { attribute: false },
    authedClient: { attribute: false },
    credentials: { attribute: false },
    runWithStepUp: { attribute: false },
    sessions: { state: true },
    passkeys: { state: true },
    remaining: { state: true },
    requests: { state: true },
    codes: { state: true },
    copied: { state: true },
    busy: { state: true },
    failures: { state: true },
    notices: { state: true },
    mismatch: { state: true },
  };
  static override styles = securityStyles;

  declare user: SignedInUser | undefined;
  declare identity: IdentityDeps | undefined;
  declare authedClient: ApiClient | undefined;
  declare credentials: CredentialsLike | undefined;
  declare runWithStepUp: StepUpRunner;
  declare sessions: SessionInfo[] | undefined;
  declare passkeys: Passkey[] | undefined;
  declare remaining: number | undefined;
  declare requests: RecoveryRequestInfo[] | undefined;
  /** A freshly generated set, in memory until the user confirms it is saved. */
  declare codes: string[] | undefined;
  declare copied: boolean;
  declare busy: string | undefined;
  declare failures: Partial<Record<SectionKey, Failure>>;
  declare notices: Partial<Record<SectionKey, string>>;
  declare mismatch: boolean;

  constructor() {
    super();
    this.user = undefined;
    this.identity = undefined;
    this.authedClient = undefined;
    this.credentials = undefined;
    this.runWithStepUp = direct;
    this.sessions = undefined;
    this.passkeys = undefined;
    this.remaining = undefined;
    this.requests = undefined;
    this.codes = undefined;
    this.copied = false;
    this.busy = undefined;
    this.failures = {};
    this.notices = {};
    this.mismatch = false;
    new LocaleController(this);
  }

  override connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  override disconnectedCallback(): void {
    this.codes = undefined;
    super.disconnectedCallback();
  }

  /** Loads every list; each section reports its own failure. */
  async load(): Promise<void> {
    const c = this.authedClient;
    if (!c) return;
    await Promise.all([
      this.guard("sessions", async () => {
        this.sessions = await listSessions(c);
      }),
      this.guard("passkeys", async () => {
        this.passkeys = await listPasskeys(c);
      }),
      this.guard("codes", async () => {
        this.remaining = await remainingRecoveryCodes(c);
      }),
      this.guard("requests", async () => {
        this.requests = await listRecoveryRequests(c);
      }),
    ]);
  }

  private async guard(section: SectionKey, fn: () => Promise<void>, busyKey?: string): Promise<boolean> {
    if (busyKey !== undefined) {
      if (this.busy !== undefined) return false;
      this.busy = busyKey;
    }
    this.failures = { ...this.failures, [section]: undefined };
    this.notices = { ...this.notices, [section]: undefined };
    try {
      await fn();
      return true;
    } catch (e) {
      this.failures = { ...this.failures, [section]: securityFailure(e) };
      return false;
    } finally {
      if (busyKey !== undefined) this.busy = undefined;
    }
  }

  private notice(section: SectionKey, text: string): void {
    this.notices = { ...this.notices, [section]: text };
  }

  override render(): TemplateResult {
    return html`<h1>${t("security.heading")}</h1>
      ${this.renderPassword()} ${this.renderSessions()} ${this.renderPasskeys()} ${this.renderCodes()} ${this.renderRequests()}`;
  }

  private renderStatus(section: SectionKey): TemplateResult {
    const n = this.notices[section];
    return html`<p class="status" role="status">${n ?? nothing}</p>${renderFailure(this.failures[section])}`;
  }

  // -- password --

  private renderPassword(): TemplateResult {
    const f = this.failures.password;
    return html`<section aria-labelledby="pw-heading">
      <h2 id="pw-heading">${t("security.password_heading")}</h2>
      <p>${t("security.password_intro")}</p>
      <form novalidate @submit=${this.onPasswordSubmit}>
        <cs-text-field name="new_password" type="password" label=${t("auth.new_password")} autocomplete="new-password" required
          .error=${fieldError(f, "password")}></cs-text-field>
        <cs-text-field name="confirm_password" type="password" label=${t("auth.confirm_password")} autocomplete="new-password" required
          .error=${this.mismatch ? t("auth.password_mismatch") : undefined}></cs-text-field>
        <div class="actions"><cs-button variant="primary" type="submit" class="change-password" ?busy=${this.busy === "password"}>${t("security.password_submit")}</cs-button></div>
      </form>
      ${this.renderStatus("password")}
    </section>`;
  }

  /** Changes the password (rev 9). Other sessions are revoked by the server; the user is told so. */
  async changePassword(): Promise<void> {
    const identity = this.identity;
    const user = this.user;
    const client = this.authedClient;
    if (!identity || !user || !client) return;
    const root = this.renderRoot as ShadowRoot;
    const pw = value(root, "new_password");
    this.mismatch = pw !== value(root, "confirm_password");
    const clear = (): void => {
      for (const n of ["new_password", "confirm_password"]) {
        const el = root.querySelector<HTMLElement & { value: string }>(`cs-text-field[name="${n}"]`);
        if (el) el.value = "";
      }
    };
    if (this.mismatch) return;
    const ok = await this.guard("password", () => this.runWithStepUp(() => changePassword(identity, client, user.tenant, user.login, pw)), "password");
    clear();
    if (ok) {
      this.notice("password", t("security.password_changed"));
      await this.guard("sessions", async () => {
        this.sessions = await listSessions(client);
      });
    }
  }

  private onPasswordSubmit(e: Event): void {
    e.preventDefault();
    void this.changePassword();
  }

  // -- sessions --

  private renderSessions(): TemplateResult {
    const list = this.sessions;
    return html`<section aria-labelledby="sessions-heading" aria-busy=${list === undefined && !this.failures.sessions ? "true" : "false"}>
      <h2 id="sessions-heading">${t("security.sessions_heading")}</h2>
      ${list
        ? html`<ul class="items sessions">
            ${list.map(
              (s) => html`<li class=${s.current ? "session current" : "session"}>
                <div>
                  <div>${s.user_agent ?? t("security.unknown_device")} ${s.current ? html`<span class="badge">(${t("security.this_session")})</span>` : nothing}</div>
                  <div class="meta">${t("security.signed_in")} ${when(s.created_at)} · ${t("security.last_seen")} ${when(s.last_seen_at)} · ${s.amr.join(", ")}</div>
                </div>
                <cs-button class="revoke" label=${t(s.current ? "security.sign_out_here" : "security.revoke_named", { device: s.user_agent ?? t("security.unknown_device") })}
                  ?busy=${this.busy === `session:${s.sid}`} @click=${() => void this.revoke(s)}>${t(s.current ? "auth.sign_out" : "security.revoke")}</cs-button>
              </li>`,
            )}
          </ul>`
        : nothing}
      ${this.renderStatus("sessions")}
    </section>`;
  }

  /** Revokes a session (rev 10). The current one acts as logout, so this tab signs out too. */
  async revoke(s: SessionInfo): Promise<void> {
    const client = this.authedClient;
    const session = this.identity?.session;
    if (!client) return;
    const ok = await this.guard(
      "sessions",
      () => (s.current ? revokeSession(client, s.sid) : this.runWithStepUp(() => revokeSession(client, s.sid))),
      `session:${s.sid}`,
    );
    if (!ok) return;
    if (s.current) {
      await session?.signedOut();
      this.dispatchEvent(new CustomEvent("cs-signed-out", { bubbles: true, composed: true }));
      return;
    }
    this.sessions = this.sessions?.filter((x) => x.sid !== s.sid);
    this.notice("sessions", t("security.session_revoked"));
  }

  // -- passkeys --

  private renderPasskeys(): TemplateResult {
    const list = this.passkeys;
    return html`<section aria-labelledby="passkeys-heading">
      <h2 id="passkeys-heading">${t("security.passkeys_heading")}</h2>
      ${list?.length === 0 ? html`<p>${t("security.passkeys_empty")}</p>` : nothing}
      ${list && list.length > 0
        ? html`<ul class="items passkeys">
            ${list.map(
              (p) => html`<li class="passkey">
                <div>
                  <div>${p.label}</div>
                  <div class="meta">${t("security.added")} ${when(p.created_at)} · ${t("security.last_used")} ${when(p.last_used_at)}</div>
                </div>
                <cs-button class="remove-passkey" label=${t("security.remove_named", { name: p.label })} ?busy=${this.busy === `passkey:${p.id}`}
                  @click=${() => void this.removePasskey(p)}>${t("security.remove")}</cs-button>
              </li>`,
            )}
          </ul>`
        : nothing}
      ${this.credentials
        ? html`<form novalidate @submit=${this.onAddPasskey}>
            <cs-text-field name="passkey_label" label=${t("security.passkey_label")} description=${t("security.passkey_label_description")} required
              .error=${this.failures.passkeys?.field === "login" ? t("security.passkey_label_invalid") : undefined}></cs-text-field>
            <div class="actions"><cs-button type="submit" class="add-passkey" ?busy=${this.busy === "passkey:add"}>${t("security.passkey_add")}</cs-button></div>
          </form>`
        : html`<p>${t("auth.passkey_unavailable")}</p>`}
      ${this.renderStatus("passkeys")}
    </section>`;
  }

  /** Registers a passkey (rev 10; needs step-up). */
  async addPasskey(): Promise<void> {
    const client = this.authedClient;
    if (!client) return;
    const label = value(this.renderRoot as ShadowRoot, "passkey_label");
    if (label.trim().length === 0 || Array.from(label.trim()).length > 100) {
      this.failures = { ...this.failures, passkeys: { field: "login" } };
      return;
    }
    let added: Passkey | undefined;
    const ok = await this.guard(
      "passkeys",
      async () => {
        added = await this.runWithStepUp(() => registerPasskey(client, this.credentials, label));
      },
      "passkey:add",
    );
    if (ok && added) {
      this.passkeys = [...(this.passkeys ?? []), added];
      this.notice("passkeys", t("security.passkey_added", { name: added.label }));
      const el = this.renderRoot.querySelector<HTMLElement & { value: string }>('cs-text-field[name="passkey_label"]');
      if (el) el.value = "";
    }
  }

  private onAddPasskey(e: Event): void {
    e.preventDefault();
    void this.addPasskey();
  }

  async removePasskey(p: Passkey): Promise<void> {
    const client = this.authedClient;
    if (!client) return;
    const ok = await this.guard("passkeys", () => this.runWithStepUp(() => deletePasskey(client, p.id)), `passkey:${p.id}`);
    if (ok) {
      this.passkeys = this.passkeys?.filter((x) => x.id !== p.id);
      this.notice("passkeys", t("security.passkey_removed", { name: p.label }));
    }
  }

  // -- recovery codes --

  private renderCodes(): TemplateResult {
    return html`<section aria-labelledby="codes-section-heading">
      <h2 id="codes-section-heading">${t("security.codes_section_heading")}</h2>
      ${this.remaining !== undefined ? html`<p class="remaining">${t("security.codes_remaining", { count: this.remaining })}</p>` : nothing}
      ${this.codes
        ? renderCodes(
            this.codes,
            this.copied,
            () => void this.copy(),
            () => {
              this.codes = undefined;
              this.copied = false;
            },
          )
        : html`<p>${t("security.codes_intro")}</p>
            <div class="actions"><cs-button class="generate-codes" ?busy=${this.busy === "codes"} @click=${() => void this.generate()}>${t("security.codes_generate")}</cs-button></div>`}
      ${this.renderStatus("codes")}
    </section>`;
  }

  /** Generates a new set (rev 10, step-up); it replaces the old set and is shown once. */
  async generate(): Promise<void> {
    const client = this.authedClient;
    if (!client) return;
    let codes: string[] | undefined;
    const ok = await this.guard(
      "codes",
      async () => {
        codes = await this.runWithStepUp(() => generateRecoveryCodes(client));
      },
      "codes",
    );
    if (ok && codes) {
      this.codes = codes;
      this.copied = false;
      this.remaining = codes.length;
    }
  }

  private async copy(): Promise<void> {
    if (this.codes) this.copied = await copyCodes(this.codes);
  }

  // -- recovery requests --

  private renderRequests(): TemplateResult {
    const list = this.requests;
    return html`<section aria-labelledby="requests-heading">
      <h2 id="requests-heading">${t("security.requests_heading")}</h2>
      ${list?.length === 0 ? html`<p>${t("security.requests_empty")}</p>` : nothing}
      ${list && list.length > 0
        ? html`<p>${t("security.requests_intro")}</p>
            <ul class="items requests">
              ${list.map(
                (r) => html`<li class="request">
                  <div>
                    <div>${t(r.method === "email" ? "security.request_email" : "security.request_device")}</div>
                    <div class="meta">
                      ${t("security.requested")} ${when(r.created_at)} · ${t("security.requester")} ${r.requester_user_agent ?? t("security.unknown_device")}
                      ${r.available_at ? html` · ${t("security.available_at")} ${when(r.available_at)}` : nothing}
                    </div>
                  </div>
                  <div class="actions">
                    ${r.method === "device_approval" && r.state === "pending"
                      ? html`<cs-button class="approve" label=${t("security.approve_named", { device: r.requester_user_agent ?? t("security.unknown_device") })}
                          ?busy=${this.busy === `approve:${r.id}`} @click=${() => void this.approve(r)}>${t("security.approve")}</cs-button>`
                      : nothing}
                    <cs-button variant="primary" class="cancel-request" ?busy=${this.busy === `cancel:${r.id}`} @click=${() => void this.cancelRequest(r)}>${t("security.cancel_request")}</cs-button>
                  </div>
                </li>`,
              )}
            </ul>`
        : nothing}
      ${this.renderStatus("requests")}
    </section>`;
  }

  async approve(r: RecoveryRequestInfo): Promise<void> {
    const client = this.authedClient;
    if (!client) return;
    const ok = await this.guard("requests", () => this.runWithStepUp(() => approveRecoveryRequest(client, r.id)), `approve:${r.id}`);
    if (ok) {
      this.requests = this.requests?.map((x) => (x.id === r.id ? { ...x, state: "granted" as const } : x));
      this.notice("requests", t("security.request_approved"));
    }
  }

  async cancelRequest(r: RecoveryRequestInfo): Promise<void> {
    const client = this.authedClient;
    if (!client) return;
    const ok = await this.guard("requests", () => cancelRecoveryRequest(client, r.id), `cancel:${r.id}`);
    if (ok) {
      this.requests = this.requests?.filter((x) => x.id !== r.id);
      this.notice("requests", t("security.request_cancelled"));
    }
  }
}

// ---- forced MFA enrolment (rev 11) ----

/**
 * Shown for an enrolment-only session (`scp: "mfa_enrolment"`, rev 11): the tenant requires MFA and the user has
 * no factor yet. The user registers a passkey and/or generates recovery codes, then signs out and signs in again.
 */
export class CsEnrolmentPage extends LitElement {
  static override properties = {
    authedClient: { attribute: false },
    session: { attribute: false },
    credentials: { attribute: false },
    runWithStepUp: { attribute: false },
    codes: { state: true },
    copied: { state: true },
    enrolled: { state: true },
    busy: { state: true },
    failure: { state: true },
    status: { state: true },
  };
  static override styles = securityStyles;

  declare authedClient: ApiClient | undefined;
  declare session: AuthSession | undefined;
  declare credentials: CredentialsLike | undefined;
  declare runWithStepUp: StepUpRunner;
  declare codes: string[] | undefined;
  declare copied: boolean;
  declare enrolled: boolean;
  declare busy: string | undefined;
  declare failure: Failure | undefined;
  declare status: string | undefined;

  constructor() {
    super();
    this.authedClient = undefined;
    this.session = undefined;
    this.credentials = undefined;
    this.runWithStepUp = direct;
    this.codes = undefined;
    this.copied = false;
    this.enrolled = false;
    this.busy = undefined;
    this.failure = undefined;
    this.status = undefined;
    new LocaleController(this);
  }

  override render(): TemplateResult {
    return html`<h1>${t("enrol.heading")}</h1>
      <section aria-labelledby="enrol-intro">
        <p id="enrol-intro">${t("enrol.intro")}</p>
        ${this.credentials
          ? html`<form novalidate @submit=${this.onPasskey}>
              <cs-text-field name="passkey_label" label=${t("security.passkey_label")} description=${t("security.passkey_label_description")} required
                .value=${t("enrol.default_label")}></cs-text-field>
              <div class="actions"><cs-button variant="primary" type="submit" class="enrol-passkey" ?busy=${this.busy === "passkey"}>${t("security.passkey_add")}</cs-button></div>
            </form>`
          : html`<p>${t("auth.passkey_unavailable")}</p>`}
        ${this.codes
          ? renderCodes(
              this.codes,
              this.copied,
              () => void this.copy(),
              () => {
                this.codes = undefined;
                this.copied = false;
              },
            )
          : html`<div class="actions"><cs-button class="enrol-codes" ?busy=${this.busy === "codes"} @click=${() => void this.generate()}>${t("security.codes_generate")}</cs-button></div>`}
        <p class="status" role="status">${this.status ?? nothing}</p>
        ${renderFailure(this.failure)}
        ${this.enrolled && !this.codes
          ? html`<p>${t("enrol.done")}</p>
              <div class="actions"><cs-button variant="primary" class="enrol-finish" ?busy=${this.busy === "finish"} @click=${() => void this.finish()}>${t("enrol.sign_in_again")}</cs-button></div>`
          : nothing}
      </section>`;
  }

  private async run(key: string, fn: () => Promise<void>): Promise<void> {
    if (this.busy !== undefined) return;
    this.busy = key;
    this.failure = undefined;
    this.status = undefined;
    try {
      await fn();
    } catch (e) {
      this.failure = securityFailure(e);
    } finally {
      this.busy = undefined;
    }
  }

  async addPasskey(): Promise<void> {
    const client = this.authedClient;
    if (!client) return;
    const label = value(this.renderRoot as ShadowRoot, "passkey_label");
    await this.run("passkey", async () => {
      const p = await this.runWithStepUp(() => registerPasskey(client, this.credentials, label));
      this.enrolled = true;
      this.status = t("security.passkey_added", { name: p.label });
    });
  }

  private onPasskey(e: Event): void {
    e.preventDefault();
    void this.addPasskey();
  }

  async generate(): Promise<void> {
    const client = this.authedClient;
    if (!client) return;
    await this.run("codes", async () => {
      this.codes = await this.runWithStepUp(() => generateRecoveryCodes(client));
      this.copied = false;
      this.enrolled = true;
    });
  }

  private async copy(): Promise<void> {
    if (this.codes) this.copied = await copyCodes(this.codes);
  }

  /** Signs out the enrolment-only session; the user signs in again normally (rev 11). */
  async finish(): Promise<void> {
    const client = this.authedClient;
    const session = this.session;
    if (!client || !session) return;
    await this.run("finish", async () => {
      await signOut(client, session);
      this.dispatchEvent(new CustomEvent("cs-signed-out", { bubbles: true, composed: true }));
    });
  }
}

// ---- account recovery (signed out) ----

type RecoveryChoice = "recovery_code" | "email" | "device_approval";

/** Device-approval requests are polled at this interval while the page waits. */
export const RECOVERY_POLL_MS = 5_000;

/**
 * Account recovery (§4, [R5], rev 10): with a recovery code (granted at once), by email link (waiting period;
 * MFA users also enter a recovery code), or by approval from a signed-in device (polled). Once granted, the user
 * sets a new password; completing it revokes every session and signs in. The grant, link token and txn stay in
 * memory only (inside the SDK's RecoveryFlow).
 */
export class CsRecoveryPage extends LitElement {
  static override properties = {
    identity: { attribute: false },
    token: { type: String },
    choice: { state: true },
    busy: { state: true },
    failure: { state: true },
    mismatch: { state: true },
    tick: { state: true },
  };
  static override styles = securityStyles;

  declare identity: IdentityDeps | undefined;
  /** Token from an emailed recovery link (`#/recover/<token>`, removed from the address bar by the shell). */
  declare token: string;
  declare choice: RecoveryChoice;
  declare busy: boolean;
  declare failure: Failure | undefined;
  declare mismatch: boolean;
  declare tick: number;

  private flowValue: RecoveryFlow | undefined;
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor() {
    super();
    this.identity = undefined;
    this.token = "";
    this.choice = "recovery_code";
    this.busy = false;
    this.failure = undefined;
    this.mismatch = false;
    this.tick = 0;
    new LocaleController(this);
  }

  /** The SDK state machine (created on first use). */
  get flow(): RecoveryFlow | undefined {
    if (!this.flowValue && this.identity) this.flowValue = new RecoveryFlow(this.identity);
    return this.flowValue;
  }

  override disconnectedCallback(): void {
    this.stopPolling();
    this.flowValue?.reset();
    super.disconnectedCallback();
  }

  override render(): TemplateResult {
    const flow = this.flow;
    const phase = flow?.phase ?? { kind: "idle" as const };
    let body: TemplateResult;
    switch (phase.kind) {
      case "idle":
        body = this.token ? this.renderLink() : this.renderStart();
        break;
      case "email_sent":
        body = html`<p role="status">${t("recover.email_sent")}</p>`;
        break;
      case "waiting":
        body = html`<p role="status" class="waiting">
            ${phase.method === "email"
              ? phase.available_at
                ? html`${t("recover.waiting_email")} ${when(phase.available_at)}`
                : t("recover.waiting_email_unknown")
              : t("recover.waiting_device")}
          </p>
          <div class="actions">
            <cs-button class="check" ?busy=${this.busy} @click=${() => void this.poll()}>${t("recover.check_again")}</cs-button>
            <cs-button variant="ghost" class="start-over" @click=${() => {
              this.startOver();
            }}>${t("recover.start_over")}</cs-button>
          </div>`;
        break;
      case "granted":
        body = this.renderNewPassword(flow?.login ?? "");
        break;
      case "expired":
      case "cancelled":
        body = html`<p role="status">${t(phase.kind === "expired" ? "recover.expired" : "recover.cancelled")}</p>
          <div class="actions"><cs-button class="start-over" @click=${() => {
            this.startOver();
          }}>${t("recover.start_over")}</cs-button></div>`;
        break;
      case "done":
        body = html`<p role="status">${t("recover.done")}</p>`;
        break;
    }
    return html`<h1>${t("recover.heading")}</h1>
      <section aria-label=${t("recover.heading")}>${body} ${renderFailure(this.failure)}</section>`;
  }

  private renderStart(): TemplateResult {
    const f = this.failure;
    const c = this.choice;
    return html`<p>${t("recover.intro")}</p>
      <form novalidate @submit=${this.onStart}>
        <fieldset>
          <legend>${t("recover.method")}</legend>
          ${(["recovery_code", "email", "device_approval"] as const).map(
            (m) => html`<label><input type="radio" name="method" value=${m} .checked=${c === m} @change=${() => {
              this.choice = m;
              this.failure = undefined;
            }} /> ${t(`recover.method_${m}`)}</label><br />`,
          )}
        </fieldset>
        <cs-text-field name="tenant" label=${t("auth.tenant")} description=${t("auth.tenant_description")} required .error=${fieldError(f, "tenant")}></cs-text-field>
        <cs-text-field name="login" label=${t("auth.login")} autocomplete="username" required .error=${fieldError(f, "login")}></cs-text-field>
        ${c === "recovery_code"
          ? html`<cs-text-field name="recovery_code" label=${t("auth.recovery_code")} description=${t("auth.recovery_code_description")} required
              autocomplete="one-time-code" .error=${fieldError(f, "recovery_code")}></cs-text-field>`
          : nothing}
        ${c === "email" ? html`<p>${t("recover.email_mfa_note")}</p>` : nothing}
        <div class="actions"><cs-button variant="primary" type="submit" class="start" ?busy=${this.busy}>${t("recover.start")}</cs-button></div>
      </form>
      <p><a href="#/sign-in">${t("recover.back_to_signin")}</a></p>`;
  }

  private renderLink(): TemplateResult {
    const f = this.failure;
    return html`<p>${t("recover.link_intro")}</p>
      <form novalidate @submit=${this.onLink}>
        <cs-text-field name="recovery_code" label=${t("recover.link_code")} description=${t("recover.link_code_description")}
          autocomplete="one-time-code" .error=${fieldError(f, "recovery_code")}></cs-text-field>
        <p>${t("recover.passkey_hint")}</p>
        <div class="actions"><cs-button variant="primary" type="submit" class="open-link" ?busy=${this.busy}>${t("recover.continue")}</cs-button></div>
      </form>`;
  }

  private renderNewPassword(login: string): TemplateResult {
    const f = this.failure;
    return html`<p>${t("recover.granted_intro")}</p>
      <form novalidate @submit=${this.onComplete}>
        <cs-text-field name="login" label=${t("auth.login")} autocomplete="username" required .value=${login} .error=${fieldError(f, "login")}></cs-text-field>
        <cs-text-field name="password" type="password" label=${t("auth.new_password")} autocomplete="new-password" required
          .error=${fieldError(f, "password")}></cs-text-field>
        <cs-text-field name="confirm" type="password" label=${t("auth.confirm_password")} autocomplete="new-password" required
          .error=${this.mismatch ? t("auth.password_mismatch") : undefined}></cs-text-field>
        <div class="actions"><cs-button variant="primary" type="submit" class="complete" ?busy=${this.busy}>${t("recover.complete")}</cs-button></div>
      </form>`;
  }

  private async step(fn: (flow: RecoveryFlow) => Promise<void>, unauthenticated: string): Promise<void> {
    const flow = this.flow;
    if (!flow || this.busy) return;
    this.busy = true;
    this.failure = undefined;
    try {
      await fn(flow);
    } catch (e) {
      this.failure = classify(e, unauthenticated);
    } finally {
      this.busy = false;
      this.tick++;
      this.syncPolling();
    }
  }

  async start(): Promise<void> {
    const root = this.renderRoot as ShadowRoot;
    const tenant = value(root, "tenant").trim().toLowerCase();
    const login = value(root, "login");
    if (!isCanonicalTenantId(tenant)) {
      this.failure = { field: "tenant" };
      return;
    }
    const choice = this.choice;
    const code = choice === "recovery_code" ? value(root, "recovery_code") : "";
    await this.step(async (flow) => {
      if (choice === "recovery_code") await flow.startWithCode(tenant, login, code);
      else if (choice === "email") await flow.startEmail(tenant, login);
      else await flow.startDeviceApproval(tenant, login);
    }, t("recover.code_failed"));
  }

  async openLink(): Promise<void> {
    const code = value(this.renderRoot as ShadowRoot, "recovery_code");
    const token = this.token;
    await this.step(async (flow) => {
      await flow.openEmailLink(token, code);
      this.token = "";
    }, t("recover.link_failed"));
  }

  async poll(): Promise<void> {
    await this.step((flow) => flow.poll(), t("recover.link_failed"));
  }

  async complete(): Promise<void> {
    const root = this.renderRoot as ShadowRoot;
    const login = value(root, "login");
    const password = value(root, "password");
    this.mismatch = password !== value(root, "confirm");
    if (this.mismatch) return;
    const identity = this.identity;
    await this.step(async (flow) => {
      await flow.complete(login, password);
      const normalized = identity ? await identity.engine.normalizeLogin(login) : login;
      this.dispatchEvent(signedInEvent({ tenant: flow.tenant, login: normalized }));
    }, t("recover.grant_failed"));
    for (const n of ["password", "confirm"]) {
      const el = root.querySelector<HTMLElement & { value: string }>(`cs-text-field[name="${n}"]`);
      if (el) el.value = "";
    }
  }

  startOver(): void {
    this.stopPolling();
    this.flowValue?.reset();
    this.token = "";
    this.failure = undefined;
    this.tick++;
  }

  /** Device approval is polled while waiting; the email waiting period is checked on demand. */
  private syncPolling(): void {
    const p = this.flowValue?.phase;
    const poll = p?.kind === "waiting" && p.method === "device_approval";
    if (poll && this.timer === undefined) {
      this.timer = setInterval(() => void this.poll(), RECOVERY_POLL_MS);
    } else if (!poll) {
      this.stopPolling();
    }
  }

  private stopPolling(): void {
    if (this.timer !== undefined) clearInterval(this.timer);
    this.timer = undefined;
  }

  private onStart(e: Event): void {
    e.preventDefault();
    void this.start();
  }

  private onLink(e: Event): void {
    e.preventDefault();
    void this.openLink();
  }

  private onComplete(e: Event): void {
    e.preventDefault();
    void this.complete();
  }
}

for (const [name, ctor] of [
  ["cs-security-page", CsSecurityPage],
  ["cs-enrolment-page", CsEnrolmentPage],
  ["cs-recovery-page", CsRecoveryPage],
] as const) {
  if (!customElements.get(name)) customElements.define(name, ctor);
}

declare global {
  interface HTMLElementTagNameMap {
    "cs-security-page": CsSecurityPage;
    "cs-enrolment-page": CsEnrolmentPage;
    "cs-recovery-page": CsRecoveryPage;
  }
}

