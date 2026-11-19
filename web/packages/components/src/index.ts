// @cs/components — shared platform web components (spec §3.5, §14.3, §14.6; contract M0 §10).
// Importing this module registers the custom elements. Components consume only @cs/sdk public types.
export { CsButton, type ButtonVariant } from "./cs-button";
export { CsDialog, type DialogCloseDetail, type DialogCloseReason } from "./cs-dialog";
export { CsErrorBanner } from "./cs-error-banner";
export { CsSpinner } from "./cs-spinner";
export { CsTextField, type TextFieldType } from "./cs-text-field";
export { LocaleController, deepActiveElement, tabbableElements } from "./shared";
