// Shared ESLint flat config for web/. Lives in its own workspace so typescript-eslint resolves the
// TypeScript 6 compiler API installed here (TypeScript 7.0, used for typecheck/build, has no JS API).
import js from "@eslint/js";
import lit from "eslint-plugin-lit";
import litA11y from "eslint-plugin-lit-a11y";
import tseslint from "typescript-eslint";

/** @param {string} tsconfigRootDir */
export function config(tsconfigRootDir) {
  return tseslint.config(
    { ignores: ["**/dist/**", "**/node_modules/**", "**/*.js", "**/*.mjs", "**/*.config.ts"] },
    js.configs.recommended,
    ...tseslint.configs.strictTypeChecked,
    ...tseslint.configs.stylisticTypeChecked,
    {
      languageOptions: {
        parserOptions: { projectService: true, tsconfigRootDir },
      },
      rules: {
        "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
        "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
        "@typescript-eslint/consistent-type-imports": "error",
        "@typescript-eslint/explicit-module-boundary-types": "error",
        "no-console": "error",
      },
    },
    {
      files: ["packages/components/**/*.ts", "apps/**/*.ts"],
      ...lit.configs["flat/recommended"],
      plugins: { lit, "lit-a11y": litA11y },
      rules: {
        // Lit binds template event listeners to the host element, so method references are safe.
        "@typescript-eslint/unbound-method": "off",
        ...lit.configs["flat/recommended"].rules,
        ...Object.fromEntries(
          Object.keys(litA11y.configs.recommended.rules).map((r) => [r, litA11y.configs.recommended.rules[r]]),
        ),
      },
    },
    {
      files: ["**/*.test.ts"],
      rules: {
        "@typescript-eslint/no-non-null-assertion": "off",
        "@typescript-eslint/explicit-module-boundary-types": "off",
      },
    },
  );
}
