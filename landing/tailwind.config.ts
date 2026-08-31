import type { Config } from "tailwindcss";

/**
 * Tailwind is layered on top of the CSS-variable token system defined in
 * app/globals.css. Every colour/type value here traces back to a token — the
 * default Tailwind palette and type scale are intentionally not shipped as-is.
 */
const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    // Replace (not extend) colours so no stock Tailwind palette leaks in.
    colors: {
      transparent: "transparent",
      current: "currentColor",
      void: "var(--void)",
      surface: "var(--surface)",
      "surface-2": "var(--surface-2)",
      ink: "var(--ink)",
      "ink-muted": "var(--ink-muted)",
      "ink-faint": "var(--ink-faint)",
      thread: "var(--thread)",
      "thread-bright": "var(--thread-bright)",
      "thread-dim": "var(--thread-dim)",
      line: "var(--line)",
    },
    extend: {
      fontFamily: {
        display: "var(--font-display)",
        body: "var(--font-body)",
        mono: "var(--font-mono)",
      },
      maxWidth: {
        prose: "68ch",
        shell: "1200px",
      },
      letterSpacing: {
        tightest: "-0.03em",
        display: "-0.02em",
        data: "0.02em",
        label: "0.24em",
      },
      transitionTimingFunction: {
        quiet: "cubic-bezier(0.22, 1, 0.36, 1)",
      },
      keyframes: {
        "caret-blink": {
          "0%, 60%": { opacity: "1" },
          "61%, 100%": { opacity: "0" },
        },
      },
      animation: {
        caret: "caret-blink 1.1s steps(1) infinite",
      },
    },
  },
  plugins: [],
};

export default config;
