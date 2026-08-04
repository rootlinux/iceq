// src/components/Brand/IceQWordmark.tsx
//
// IceQ Wordmark — Ice Bloom Q mark + "IceQ" text composition.
//
// Variants:
//   horizontal  — mark left of text (default)
//   stacked     — mark above text
//
// The wordmark keeps "IceQ" as readable text, not outlines.
// Spacing and alignment are deliberate for each variant.

import { IceQMark } from "./IceQMark";

interface IceQWordmarkProps {
  /** Layout variant. */
  variant?: "horizontal" | "stacked";
  /** Overall size of the composition. */
  size?: "sm" | "md" | "lg" | "xl" | "hero";
  className?: string;
  /** Accessible label — describes the entire wordmark. */
  label?: string;
  /** Force aria-hidden. */
  "aria-hidden"?: boolean;
  /** Full-color mark. */
  fullColor?: boolean;
  /** Monochrome mark + text. */
  monochrome?: boolean;
  /** Compact mark variant (favicon-safe). */
  compact?: boolean;
}

// ── Size map for mark + text ──────────────────────────────────────────
const SIZE_CONFIG = {
  sm:   { mark: 20, text: "text-base",   gap: "gap-1.5" },
  md:   { mark: 32, text: "text-xl",     gap: "gap-2" },
  lg:   { mark: 48, text: "text-3xl",    gap: "gap-3" },
  xl:   { mark: 72, text: "text-5xl",    gap: "gap-4" },
  hero: { mark: 150, text: "text-5xl",   gap: "gap-4" },
} as const;

const STACKED_SIZE_CONFIG = {
  sm:   { mark: 24,  text: "text-sm",    gap: "gap-1" },
  md:   { mark: 40,  text: "text-lg",    gap: "gap-1.5" },
  lg:   { mark: 64,  text: "text-2xl",   gap: "gap-2" },
  xl:   { mark: 96,  text: "text-4xl",   gap: "gap-3" },
  hero: { mark: 150, text: "text-5xl",   gap: "gap-3" },
} as const;

export function IceQWordmark({
  variant = "horizontal",
  size = "md",
  className = "",
  label = "IceQ",
  "aria-hidden": ariaHidden,
  fullColor: fullColorProp,
  monochrome = false,
  compact = false,
}: IceQWordmarkProps): JSX.Element {
  const isHorizontal = variant === "horizontal";
  const config = isHorizontal ? SIZE_CONFIG[size] : STACKED_SIZE_CONFIG[size];
  const useColor = !monochrome && fullColorProp !== false;

  const textStyle: React.CSSProperties = {
    fontFamily: "ui-rounded, SF Pro Rounded, SF Pro Display, Inter, system-ui, sans-serif",
    fontWeight: 700,
    letterSpacing: "-0.02em",
    color: useColor ? "#F3F7FF" : "currentColor",
  };

  const containerClass = isHorizontal
    ? `inline-flex items-center ${config.gap} ${className}`
    : `inline-flex flex-col items-center ${config.gap} ${className}`;

  return (
    <div
      className={containerClass}
      role={ariaHidden ? "presentation" : "img"}
      aria-label={ariaHidden ? undefined : label}
      aria-hidden={ariaHidden || undefined}
    >
      <IceQMark
        size={config.mark}
        fullColor={fullColorProp}
        monochrome={monochrome}
        compact={compact}
        aria-hidden={true}
      />
      <span
        className={`${config.text} select-none leading-none`}
        style={textStyle}
      >
        IceQ
      </span>
    </div>
  );
}

export default IceQWordmark;
