// Shell message catalog (English). Every user-facing string in the shell goes through t() with these keys.
import { registerMessages } from "@cs/sdk";

export const SHELL_MESSAGES_EN = {
  "shell.product_name": "Cloud System",
  "shell.skip_to_main": "Skip to main content",
  "shell.global_nav": "Global",
  "shell.launcher": "Applications",
  "shell.launcher_heading": "Applications",
  "shell.launcher_placeholder": "Installed applications will appear here.",
  "shell.notifications": "Notifications",
  "shell.notifications_empty": "No notifications",
  "shell.home_heading": "Welcome",
  "shell.status_heading": "Service status",
  "shell.status_checking": "Checking service status…",
  "shell.status_ready": "The service is ready.",
  "shell.status_not_ready": "The service is not ready.",
  "shell.status_recheck": "Check again",
  "shell.dev_link": "Developer: error states",
  "dev.heading": "Error states",
  "dev.intro": "Sample problems rendered by the error banner. Use this page to review wording, layout and screen reader output.",
  "dev.samples_heading": "Sample problems",
  "dev.pipeline_heading": "Client pipeline",
  "dev.pipeline_intro": "These buttons send a request through ApiClient to a simulated server, so the banner shows what the client produced.",
  "dev.sim_malformed": "Malformed problem body",
  "dev.sim_html": "HTML error page (502)",
  "dev.sim_network": "Network failure",
  "dev.sim_rate_limited": "Rate limited, then success",
  "dev.sim_success": "Request succeeded after {attempts} attempts.",
  "dev.components_heading": "Components",
  "dev.field_label": "Folder name",
  "dev.field_description": "Up to 255 characters.",
  "dev.field_error": "Enter a folder name.",
  "dev.open_dialog": "Open dialog",
  "dev.dialog_heading": "Example dialog",
  "dev.dialog_body": "Press Escape or use the close button. Focus returns to the button that opened the dialog.",
  "dev.dialog_ok": "OK",
  "dev.back_home": "Back to home",
} as const;

export type ShellMessageKey = keyof typeof SHELL_MESSAGES_EN;

export function registerShellMessages(): void {
  registerMessages("en", SHELL_MESSAGES_EN);
}
