// Design tokens (spec §14.3) exported as CSS custom properties, light and dark themes.
// Contrast requirements (WCAG 2.2 AA) are encoded as data in CONTRAST_REQUIREMENTS and checked by unit tests.

export type ColorToken =
  | "bg"
  | "surface"
  | "surface-raised"
  | "text"
  | "text-muted"
  | "border"
  | "border-strong"
  | "primary"
  | "primary-hover"
  | "on-primary"
  | "danger"
  | "danger-hover"
  | "on-danger"
  | "danger-surface"
  | "danger-text"
  | "success-surface"
  | "success-text"
  | "focus-ring"
  | "backdrop";

export type ColorScheme = Readonly<Record<ColorToken, string>>;

export const LIGHT_COLORS: ColorScheme = {
  bg: "#ffffff",
  surface: "#f5f6f8",
  "surface-raised": "#ffffff",
  text: "#1a1d23",
  "text-muted": "#545b66",
  border: "#d5d9e0",
  "border-strong": "#6b7280",
  primary: "#0b57d0",
  "primary-hover": "#0842a0",
  "on-primary": "#ffffff",
  danger: "#b3261e",
  "danger-hover": "#8c1d18",
  "on-danger": "#ffffff",
  "danger-surface": "#fcebea",
  "danger-text": "#8c1d18",
  "success-surface": "#e6f4ea",
  "success-text": "#14632c",
  "focus-ring": "#0b57d0",
  backdrop: "rgba(15, 17, 21, 0.55)",
};

export const DARK_COLORS: ColorScheme = {
  bg: "#111318",
  surface: "#1a1d24",
  "surface-raised": "#22262e",
  text: "#e8eaee",
  "text-muted": "#a9b0bb",
  border: "#343a45",
  "border-strong": "#8b93a1",
  primary: "#8ab4f8",
  "primary-hover": "#aecbfa",
  "on-primary": "#0b1a33",
  danger: "#f2b8b5",
  "danger-hover": "#f9dedc",
  "on-danger": "#3a0b08",
  "danger-surface": "#3b1614",
  "danger-text": "#ffd9d6",
  "success-surface": "#12301c",
  "success-text": "#a8dab5",
  "focus-ring": "#8ab4f8",
  backdrop: "rgba(0, 0, 0, 0.65)",
};

export interface ContrastRequirement {
  readonly fg: ColorToken;
  readonly bg: ColorToken;
  /** 4.5 for normal text (SC 1.4.3), 3 for UI component boundaries and focus indicators (SC 1.4.11, 2.4.13 guidance). */
  readonly min: 4.5 | 3;
  readonly use: string;
}

/** Foreground/background pairs the components actually render. Every pair must pass in both themes. */
export const CONTRAST_REQUIREMENTS: readonly ContrastRequirement[] = [
  { fg: "text", bg: "bg", min: 4.5, use: "body text" },
  { fg: "text", bg: "surface", min: 4.5, use: "text on surfaces" },
  { fg: "text", bg: "surface-raised", min: 4.5, use: "text in dialogs" },
  { fg: "text-muted", bg: "bg", min: 4.5, use: "descriptions" },
  { fg: "text-muted", bg: "surface", min: 4.5, use: "descriptions on surfaces" },
  { fg: "text-muted", bg: "surface-raised", min: 4.5, use: "descriptions in dialogs" },
  { fg: "on-primary", bg: "primary", min: 4.5, use: "primary button label" },
  { fg: "on-primary", bg: "primary-hover", min: 4.5, use: "primary button label (hover)" },
  { fg: "on-danger", bg: "danger", min: 4.5, use: "danger button label" },
  { fg: "on-danger", bg: "danger-hover", min: 4.5, use: "danger button label (hover)" },
  { fg: "primary", bg: "bg", min: 4.5, use: "secondary/ghost button label" },
  { fg: "primary", bg: "surface", min: 4.5, use: "secondary button label on surfaces" },
  { fg: "danger", bg: "bg", min: 4.5, use: "field error text" },
  { fg: "danger", bg: "surface-raised", min: 4.5, use: "field error text in dialogs" },
  { fg: "danger-text", bg: "danger-surface", min: 4.5, use: "error banner text" },
  { fg: "success-text", bg: "success-surface", min: 4.5, use: "status text" },
  { fg: "border-strong", bg: "bg", min: 3, use: "text field border" },
  { fg: "border-strong", bg: "surface-raised", min: 3, use: "text field border in dialogs" },
  { fg: "focus-ring", bg: "bg", min: 3, use: "focus indicator" },
  { fg: "focus-ring", bg: "surface", min: 3, use: "focus indicator on surfaces" },
  { fg: "focus-ring", bg: "surface-raised", min: 3, use: "focus indicator in dialogs" },
  { fg: "danger", bg: "danger-surface", min: 3, use: "error banner border" },
  { fg: "primary", bg: "surface", min: 3, use: "spinner arc" },
];

export const TYPOGRAPHY = {
  "font-family": 'system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", "Noto Sans Thai", sans-serif',
  "font-family-mono": 'ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace',
  "font-size-sm": "0.875rem",
  "font-size-md": "1rem",
  "font-size-lg": "1.25rem",
  "font-size-xl": "1.5rem",
  "line-height-tight": "1.25",
  "line-height-normal": "1.5",
  "font-weight-regular": "400",
  "font-weight-medium": "500",
  "font-weight-bold": "650",
} as const;

export const SPACING = {
  "space-0": "0",
  "space-1": "0.25rem",
  "space-2": "0.5rem",
  "space-3": "0.75rem",
  "space-4": "1rem",
  "space-5": "1.5rem",
  "space-6": "2rem",
  "space-7": "3rem",
} as const;

export const RADII = {
  "radius-sm": "4px",
  "radius-md": "8px",
  "radius-lg": "12px",
  "radius-full": "9999px",
} as const;

export const FOCUS = {
  "focus-ring-width": "2px",
  "focus-ring-offset": "2px",
} as const;

export const MOTION = {
  "motion-duration-fast": "120ms",
  "motion-duration-normal": "200ms",
  "motion-duration-spin": "800ms",
  "motion-easing-standard": "cubic-bezier(0.2, 0, 0, 1)",
} as const;

export const SIZES = {
  /** WCAG 2.2 SC 2.5.8 requires 24×24 CSS px; we use 40 for comfortable targets. */
  "target-min": "40px",
  "content-max-width": "72rem",
} as const;

export const TOKEN_PREFIX = "--cs-";

/** CSS custom property name for a token, e.g. `cssVar("color-text")` → `var(--cs-color-text)`. */
export function cssVar(name: string): string {
  return `var(${TOKEN_PREFIX}${name})`;
}

function decls(entries: Readonly<Record<string, string>>, group = ""): string {
  return Object.entries(entries)
    .map(([k, v]) => `  ${TOKEN_PREFIX}${group}${k}: ${v};`)
    .join("\n");
}

/**
 * Stylesheet defining all tokens on :root.
 * Theme selection: `data-theme="light|dark"` on <html> wins; otherwise `prefers-color-scheme`.
 * `prefers-reduced-motion: reduce` sets every duration to 0.
 */
export function tokensCss(): string {
  const shared = [decls(TYPOGRAPHY), decls(SPACING), decls(RADII), decls(FOCUS), decls(MOTION), decls(SIZES)].join("\n");
  const light = decls(LIGHT_COLORS, "color-");
  const dark = decls(DARK_COLORS, "color-");
  return `:root {
${shared}
${light}
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
${dark}
    color-scheme: dark;
  }
}
:root[data-theme="dark"] {
${dark}
  color-scheme: dark;
}
@media (prefers-reduced-motion: reduce) {
  :root {
    ${TOKEN_PREFIX}motion-duration-fast: 0ms;
    ${TOKEN_PREFIX}motion-duration-normal: 0ms;
  }
}
`;
}

/** Installs the token stylesheet into a document once. */
export function installTokens(doc: Document = document): void {
  if (doc.getElementById("cs-design-tokens")) return;
  const style = doc.createElement("style");
  style.id = "cs-design-tokens";
  style.textContent = tokensCss();
  doc.head.appendChild(style);
}

// ---- WCAG contrast (2.x relative luminance) ----

function parseHex(hex: string): [number, number, number] {
  const m = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!m?.[1]) throw new TypeError(`not a #rrggbb color: ${hex}`);
  const n = parseInt(m[1], 16);
  return [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
}

/** WCAG relative luminance of an opaque #rrggbb color. */
export function relativeLuminance(hex: string): number {
  const [r, g, b] = parseHex(hex).map((c) => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG contrast ratio between two opaque colors, from 1 to 21. */
export function contrastRatio(a: string, b: string): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}
