// Tailwind config — the visual style is locked to a dark, ICQ-inspired
// palette. Tokens are defined here so component code reads
// `bg-surface` / `text-accent` rather than hard-coded hexes; this lets
// us shift the entire theme in one place if we ever add a light mode.
import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Backgrounds. `bg` is the page, `surface` is the chat area,
        // `surface-2` is the sidebar and modal backdrops.
        bg: "#0a0a0a",
        surface: "#1a1a1a",
        "surface-2": "#141414",
        // Hairline / divider. Strong enough to delimit cards without
        // dominating the eye.
        border: "#2a2a2a",
        // IceQ teal — accent for links, active states, the
        // presence-online dot, etc.
        accent: "#00b4d8",
        // Text. Primary is high-contrast; secondary is for
        // timestamps and helper text.
        text: "#e5e5e5",
        "text-2": "#888888",
        // Presence states. Kept in tailwind so a single class
        // change (PresenceDot) handles the whole set.
        "presence-online": "#22c55e",
        "presence-away": "#eab308",
        "presence-dnd": "#ef4444",
        "presence-offline": "#6b7280",
      },
      fontFamily: {
        sans: [
          "Inter",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
      },
      width: {
        sidebar: "280px",
      },
    },
  },
  plugins: [],
} satisfies Config;
