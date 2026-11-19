import { describe, expect, it } from "vitest";
import {
  CONTRAST_REQUIREMENTS,
  DARK_COLORS,
  LIGHT_COLORS,
  contrastRatio,
  installTokens,
  relativeLuminance,
  tokensCss,
  type ColorScheme,
} from "./tokens";

describe("contrast math", () => {
  it("matches the WCAG reference values", () => {
    expect(relativeLuminance("#000000")).toBe(0);
    expect(relativeLuminance("#ffffff")).toBeCloseTo(1, 10);
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 10);
    expect(contrastRatio("#ffffff", "#ffffff")).toBe(1);
    // #767676 on white is the well-known 4.54:1 boundary colour.
    expect(contrastRatio("#767676", "#ffffff")).toBeCloseTo(4.54, 2);
  });

  it("rejects non-hex colours", () => {
    expect(() => relativeLuminance("red")).toThrow(TypeError);
  });
});

describe.each([
  ["light", LIGHT_COLORS],
  ["dark", DARK_COLORS],
] as [string, ColorScheme][])("%s theme meets WCAG 2.2 AA", (_name, scheme) => {
  it.each(CONTRAST_REQUIREMENTS.map((r) => [`${r.fg} on ${r.bg} (${r.use})`, r] as const))("%s", (_label, r) => {
    const ratio = contrastRatio(scheme[r.fg], scheme[r.bg]);
    expect(ratio, `${r.fg} on ${r.bg} = ${ratio.toFixed(2)}`).toBeGreaterThanOrEqual(r.min);
  });
});

describe("tokensCss", () => {
  const css = tokensCss();

  it("defines every colour token for both themes", () => {
    for (const k of Object.keys(LIGHT_COLORS)) {
      expect(css).toContain(`--cs-color-${k}: ${LIGHT_COLORS[k as keyof ColorScheme]};`);
      expect(css).toContain(`--cs-color-${k}: ${DARK_COLORS[k as keyof ColorScheme]};`);
    }
  });

  it("defines typography, spacing, radii, focus and motion tokens", () => {
    for (const name of ["font-family", "font-size-md", "space-4", "radius-md", "focus-ring-width", "motion-duration-fast"]) {
      expect(css).toContain(`--cs-${name}:`);
    }
  });

  it("supports explicit and system dark mode and reduced motion", () => {
    expect(css).toContain('[data-theme="dark"]');
    expect(css).toContain("prefers-color-scheme: dark");
    expect(css).toMatch(/prefers-reduced-motion: reduce[\s\S]*--cs-motion-duration-normal: 0ms/);
  });

  it("installs once into a document", () => {
    installTokens(document);
    installTokens(document);
    expect(document.querySelectorAll("#cs-design-tokens")).toHaveLength(1);
  });
});
