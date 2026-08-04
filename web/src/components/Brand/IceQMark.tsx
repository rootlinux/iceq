// src/components/Brand/IceQMark.tsx
//
// Ice Bloom Q — the IceQ brand mark.
//
// Six rounded ice-bloom lobes orbit a compact central point.
// The lower-right lobe anchors a restrained Q tail that flows out in one
// continuous curve from inside the lobe body — never floating separately.
//
// Variants:
//   fullColor  — full palette (default)
//   monochrome — single color via currentColor
//   compact    — thicker strokes, bolder geometry for favicon/small sizes
//
// Accessible: pass `title` for labelled mode; omit for decorative (aria-hidden).

interface IceQMarkProps {
  /** Pixel size or preset. */
  size?: number | "sm" | "md" | "lg" | "xl" | "hero";
  className?: string;
  /** Accessible title — when set the SVG is labelled; omit for decorative. */
  title?: string;
  /** Accessible description (used with title). */
  description?: string;
  /** Force aria-hidden (overrides title labelling). */
  "aria-hidden"?: boolean;
  /** Full-color palette. Default true. */
  fullColor?: boolean;
  /** Single-color mode (uses currentColor). */
  monochrome?: boolean;
  /** Compact variant — bolder geometry for favicon/small sizes. */
  compact?: boolean;
}

// ── Palette ────────────────────────────────────────────────────────────
const PALETTE = {
  navy: "#071A4D",
  electric: "#35D5F4",
  violet: "#735CFF",
  magenta: "#F13CA8",
  mint: "#21D6A0",
} as const;

// ── Size presets ───────────────────────────────────────────────────────
const SIZE_MAP: Record<string, number> = {
  sm: 24,
  md: 48,
  lg: 72,
  xl: 120,
  hero: 150,
};

function resolveSize(size?: number | "sm" | "md" | "lg" | "xl" | "hero"): number {
  if (typeof size === "number") return size;
  if (size && size in SIZE_MAP) return SIZE_MAP[size]!;
  return 64;
}

// ── Lobe geometry ─────────────────────────────────────────────────────
//
// All six lobes share one smooth rounded bloom-petal shape pointing UP
// from centre (50,50).  The silhouette reads as an abstract frozen bloom,
// not a butterfly.
//
//   base width ≈ 8   (46 → 54 near centre)
//   max width  ≈ 28  (36 → 64 at mid-height)
//   tip        ≈ y=5 (50,5)
const LOBE =
  "M46,48 " +
  "C40,45 36,38 36,28 " +
  "C36,18 42,8 50,5 " +
  "C58,8 64,18 64,28 " +
  "C64,38 60,45 54,48 " +
  "Z";

// ── Q-tail stroke ─────────────────────────────────────────────────────
//
// A single continuous curve that starts **inside** the 120° lobe body
// and sweeps beyond its tip, forming the Q descender.  Because the
// stroke origin is well within the lobe fill, the tail reads as
// structurally connected at every size.
//
//   origin  ≈ 73,64   (≈60 % of lobe radial extent)
//   control ≈ 85,66
//   end     ≈ 92,82
const QTAIL = "M73,64 Q85,66 92,82";

// ── Angular positions (clockwise from top) ─────────────────────────────
const ANGLES = [0, 60, 120, 180, 240, 300];

// ── Helpers ────────────────────────────────────────────────────────────

let _id = 0;
function uid(): string {
  return `iqm-${++_id}`;
}

// ── Component ──────────────────────────────────────────────────────────

export function IceQMark({
  size,
  className = "",
  title,
  description,
  "aria-hidden": ariaHidden,
  fullColor: fullColorProp,
  monochrome = false,
  compact = false,
}: IceQMarkProps): JSX.Element {
  const px = resolveSize(size);
  const isLabelled = !!title && !ariaHidden;
  const useColor = !monochrome && fullColorProp !== false;
  const gid = uid();

  // Lobe colours clockwise from top:
  // 0° ice · 60° ice · 120° magenta (Q-tail) · 180° violet · 240° violet · 300° ice
  const fills = useColor
    ? [PALETTE.electric, PALETTE.electric, PALETTE.magenta, PALETTE.violet, PALETTE.violet, PALETTE.electric]
    : Array<string>(6).fill("currentColor");

  const tailW = compact ? 4.5 : 3;
  const centreR = compact ? 2.8 : 2;

  return (
    <svg
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      width={px}
      height={px}
      className={className}
      aria-hidden={ariaHidden || !isLabelled ? true : undefined}
      aria-labelledby={isLabelled ? `iqm-ttl-${gid}` : undefined}
      aria-describedby={isLabelled && description ? `iqm-dsc-${gid}` : undefined}
      role={isLabelled ? "img" : "presentation"}
    >
      {/* ── Accessibility ──────────────────────────────────────────── */}
      {isLabelled && (
        <>
          <title id={`iqm-ttl-${gid}`}>{title}</title>
          {description && <desc id={`iqm-dsc-${gid}`}>{description}</desc>}
        </>
      )}

      {/* ── Subtle centre glow (large full-colour only) ─────────────── */}
      {useColor && !compact && (
        <defs>
          <radialGradient id={`${gid}-glow`} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={PALETTE.navy} stopOpacity="0" />
            <stop offset="100%" stopColor={PALETTE.navy} stopOpacity="0.06" />
          </radialGradient>
          <radialGradient id={`${gid}-dot`} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={PALETTE.mint} stopOpacity="1" />
            <stop offset="100%" stopColor={PALETTE.mint} stopOpacity="0.35" />
          </radialGradient>
        </defs>
      )}

      {/* ── Background disc ────────────────────────────────────────── */}
      {!compact && (
        <circle cx="50" cy="50" r="44" fill={useColor ? `url(#${gid}-glow)` : "none"} />
      )}

      {/* ── Six ice-bloom lobes ─────────────────────────────────────── */}
      {ANGLES.map((angle, i) => {
        const isQ = i === 2; // 120° — lower-right
        const fill = fills[i];
        const lobe = (
          <g key={angle} transform={`rotate(${angle},50,50)`}>
            <path d={LOBE} fill={fill} opacity={useColor ? 0.88 : 1} />
          </g>
        );

        // Q-tail: same standard lobe + connected stroke from inside it
        if (isQ) {
          return (
            <g key={angle}>
              {lobe}
              <path
                d={QTAIL}
                stroke={useColor ? PALETTE.magenta : "currentColor"}
                strokeWidth={tailW}
                strokeLinecap="round"
                fill="none"
                opacity={useColor ? 0.88 : 1}
              />
            </g>
          );
        }

        return lobe;
      })}

      {/* ── Compact centre point ────────────────────────────────────── */}
      <circle
        cx="50"
        cy="50"
        r={centreR}
        fill={useColor && !compact ? `url(#${gid}-dot)` : useColor ? PALETTE.mint : "currentColor"}
      />
    </svg>
  );
}

export default IceQMark;
