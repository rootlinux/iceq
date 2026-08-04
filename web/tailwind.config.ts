// IceQ Encrypted Aurora design tokens.
//
// Cinematic encrypted-communication palette inspired by:
//   light moving under polar ice · encrypted radio transmission
//   optical instruments · deep ocean darkness · aurora refraction
//
// Tokens use a three-level naming scheme:
//   bg-*     background hierarchy (abyss → depth → surface)
//   text-*   text hierarchy (primary → secondary → tertiary)
//   accent-* semantic accents (electric, aurora, secure, warning, destructive)
//
// Backward-compatible aliases preserve existing component code.
import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // ── Background hierarchy (deepest → most elevated) ─────────────
        "abyss": "#050713",         // Deepest page background
        "deep-ice": "#0A1024",      // Main content planes
        "cobalt": "#101B3D",        // Elevated surfaces, cards
        "cobalt-hover": "#16224A",  // Interactive surface hover
        "cobalt-active": "#1C2A58", // Interactive surface active

        // ── Borders & separators ────────────────────────────────────────
        "ice-border": "#1A2A50",    // Subtle hairline
        "ice-border-light": "#223566", // Brighter hairline for active states

        // ── Text hierarchy ──────────────────────────────────────────────
        "frozen": "#F3F7FF",        // Primary high-contrast text (frozen white)
        "mist": "#9EADCB",          // Secondary text
        "mist-dim": "#6B7DA0",      // Tertiary, placeholders, disabled

        // ── Accent: Electric Ice (primary brand accent) ─────────────────
        "electric": "#59D8FF",      // Primary accent — links, send, active
        "electric-dim": "rgba(89, 216, 255, 0.12)",
        "electric-glow": "rgba(89, 216, 255, 0.22)",

        // ── Accent: Aurora (secondary decorative + verification) ────────
        "aurora-violet": "#8B6CFF",
        "aurora-violet-dim": "rgba(139, 108, 255, 0.12)",
        "aurora-magenta": "#E95CFF",
        "aurora-magenta-dim": "rgba(233, 92, 255, 0.10)",

        // ── Semantic ────────────────────────────────────────────────────
        "secure-mint": "#4CE1A1",   // Success, verified, online
        "secure-mint-dim": "rgba(76, 225, 161, 0.12)",
        "warning": "#FFBC5C",       // Caution, away presence
        "warning-dim": "rgba(255, 188, 92, 0.12)",
        "destructive": "#FF657A",   // Danger, errors, DND
        "destructive-dim": "rgba(255, 101, 122, 0.12)",
        "offline": "#4B5B70",       // Offline / neutral

        // ── Backward-compatible aliases ─────────────────────────────────
        // Map old token names → new Encrypted Aurora values
        // so existing component code continues to work verbatim.
        "bg": "#050713",
        "polar": "#050713",
        "deep": "#0A1024",
        "surface": "#0A1024",
        "frost": "#101B3D",
        "surface-2": "#101B3D",
        "frost-hover": "#16224A",
        "frost-active": "#1C2A58",
        "border": "#1A2A50",
        "signal-border": "#1A2A50",
        "accent": "#59D8FF",
        "signal": "#59D8FF",
        "signal-dim": "rgba(89, 216, 255, 0.12)",
        "signal-glow": "rgba(89, 216, 255, 0.22)",
        "aurora": "#8B6CFF",
        "aurora-dim": "rgba(139, 108, 255, 0.12)",
        "text": "#F3F7FF",
        "ice": "#F3F7FF",
        "text-2": "#9EADCB",
        "quiet": "#9EADCB",
        "muted": "#6B7DA0",
        "secure": "#4CE1A1",
        "secure-dim": "rgba(76, 225, 161, 0.12)",
        "presence-online": "#4CE1A1",
        "presence-away": "#FFBC5C",
        "presence-dnd": "#FF657A",
        "presence-offline": "#4B5B70",
        "danger": "#FF657A",
      },

      // ── Typography ──────────────────────────────────────────────────
      fontFamily: {
        // Display / brand face: system rounded / humanist for headings.
        display: [
          "ui-rounded",
          "SF Pro Rounded",
          "SF Pro Display",
          "Inter",
          "system-ui",
          "-apple-system",
          "sans-serif",
        ],
        // Interface / body: system sans-serif with clean rendering.
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "SF Pro Text",
          "Segoe UI",
          "Inter",
          "system-ui",
          "sans-serif",
        ],
        // Technical data: monospace for UINs, fingerprints, safety numbers.
        mono: [
          "SFMono-Regular",
          "Cascadia Code",
          "Roboto Mono",
          "Consolas",
          "ui-monospace",
          "monospace",
        ],
      },

      // ── Spacing scale (4px base) ────────────────────────────────────
      spacing: {
        "0": "0",
        "0.5": "2px",
        "1": "4px",
        "1.5": "6px",
        "2": "8px",
        "2.5": "10px",
        "3": "12px",
        "3.5": "14px",
        "4": "16px",
        "5": "20px",
        "6": "24px",
        "7": "28px",
        "8": "32px",
        "9": "36px",
        "10": "40px",
        "12": "48px",
        "14": "56px",
        "16": "64px",
        "20": "80px",
        "24": "96px",
        "28": "112px",
        "32": "128px",
        "36": "144px",
        "40": "160px",
        "44": "176px",
        "48": "192px",
        "52": "208px",
        "56": "224px",
        "60": "240px",
        "64": "256px",
        "72": "288px",
        "80": "320px",
        "96": "384px",
      },

      // ── Border radius scale ─────────────────────────────────────────
      borderRadius: {
        "none": "0",
        "xs": "2px",
        "sm": "4px",
        "md": "6px",
        "lg": "10px",
        "xl": "14px",
        "2xl": "20px",
        "3xl": "28px",
        "full": "9999px",
      },

      // ── Shadows (deep, atmospheric) ─────────────────────────────────
      boxShadow: {
        "none": "none",
        "sm": "0 1px 3px rgba(0, 0, 0, 0.4)",
        "md": "0 4px 16px rgba(0, 0, 0, 0.5)",
        "lg": "0 8px 32px rgba(0, 0, 0, 0.6)",
        "xl": "0 16px 48px rgba(0, 0, 0, 0.7)",
        // Aurora glow — soft, directional light behind focal elements
        "aurora": "0 0 60px rgba(139, 108, 255, 0.15), 0 0 120px rgba(89, 216, 255, 0.08)",
        "aurora-sm": "0 0 30px rgba(139, 108, 255, 0.12)",
        // Electric ice focus ring
        "electric": "0 0 0 2px rgba(89, 216, 255, 0.35)",
        "electric-sm": "0 0 0 1px rgba(89, 216, 255, 0.25)",
        // Destructive focus
        "destructive-glow": "0 0 0 2px rgba(255, 101, 122, 0.35)",
      },

      // ── Animation timing ────────────────────────────────────────────
      transitionDuration: {
        "75": "75ms",
        "100": "100ms",
        "150": "150ms",
        "200": "200ms",
        "300": "300ms",
        "500": "500ms",
        "700": "700ms",
        "1000": "1000ms",
        "1500": "1500ms",
        "2000": "2000ms",
      },

      // ── Layout ──────────────────────────────────────────────────────
      width: {
        "rail": "64px",            // Identity rail width
        "sidebar": "300px",        // Conversation field width
      },
      maxWidth: {
        "auth-form": "380px",
        "setup-card": "560px",
        "modal-sm": "400px",
        "modal-md": "480px",
        "modal-lg": "600px",
        "chat-msg": "72%",
      },

      // ── Backdrop blur scale ─────────────────────────────────────────
      backdropBlur: {
        "xs": "2px",
        "sm": "4px",
        "md": "8px",
        "lg": "12px",
        "xl": "20px",
      },

      // ── Keyframes for Cipher Ring & aurora effects ──────────────────
      keyframes: {
        "cipher-pulse": {
          "0%, 100%": { opacity: "0.3", transform: "scale(0.95)" },
          "50%": { opacity: "1", transform: "scale(1.05)" },
        },
        "cipher-rotate": {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        "aurora-shift": {
          "0%, 100%": { opacity: "0.4" },
          "50%": { opacity: "0.7" },
        },
        "channel-glow": {
          "0%, 100%": { opacity: "0.3" },
          "50%": { opacity: "0.6" },
        },
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "reveal": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
      },
      animation: {
        "cipher-pulse": "cipher-pulse 3s ease-in-out infinite",
        "cipher-rotate": "cipher-rotate 12s linear infinite",
        "aurora-shift": "aurora-shift 6s ease-in-out infinite",
        "channel-glow": "channel-glow 4s ease-in-out infinite",
        "fade-up": "fade-up 400ms ease-out",
        "reveal": "reveal 300ms ease-out",
      },
    },
  },
  plugins: [],
} satisfies Config;
