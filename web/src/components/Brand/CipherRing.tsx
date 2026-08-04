// src/components/Brand/CipherRing.tsx
//
// IceQ Cipher Ring — the signature brand mark.
//
// A broken circular ice ring where the gap subtly forms the tail of a "Q".
// A small transmission pulse travels around the ring.
//
// States (via `data-state`):
//   disconnected  — grey track, pulse hidden (default)
//   connecting    — dim track, fast pulse
//   secure        — electric ice track + glow, slow pulse
//   warning       — amber track, rapid pulse (reconnecting)
//
// Sizes:
//   auth  — large focal element (login/register)
//   rail  — compact identity rail mark
//   empty — empty-state placeholder

interface CipherRingProps {
  size?: "auth" | "rail" | "empty";
  state?: "disconnected" | "connecting" | "secure" | "warning";
  className?: string;
}

export function CipherRing({
  size = "auth",
  state = "disconnected",
  className = "",
}: CipherRingProps): JSX.Element {
  const sizeClass =
    size === "auth"
      ? "cipher-ring--auth"
      : size === "rail"
        ? "cipher-ring--rail"
        : "cipher-ring--empty";

  return (
    <div
      className={`cipher-ring ${sizeClass} ${className}`}
      data-state={state}
      role="img"
      aria-hidden="true"
    >
      <svg
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="h-full w-full"
      >
        {/* ── Outer ring track ─────────────────────────────────────── */}
        <circle
          cx="50"
          cy="50"
          r="42"
          className="cipher-ring-track"
          stroke="currentColor"
          strokeWidth="1.5"
          fill="none"
          opacity="0.3"
        />

        {/* ── Main Cipher Ring — broken arc forming the Q ──────────── */}
        {/* The ring is drawn as a path with a gap from ~135° to ~170°
            where the "Q tail" extends inward. */}
        <path
          d={describeRingPath(50, 50, 38, -55, 220)}
          className="cipher-ring-track"
          stroke="currentColor"
          strokeWidth="2.5"
          fill="none"
          strokeLinecap="round"
        />

        {/* ── Q tail — the broken segment extends inward ───────────── */}
        <path
          d="M76 24 L66 34"
          className="cipher-ring-track"
          stroke="currentColor"
          strokeWidth="2.5"
          fill="none"
          strokeLinecap="round"
        />

        {/* ── Inner track (secondary ring) ──────────────────────────── */}
        <circle
          cx="50"
          cy="50"
          r="32"
          className="cipher-ring-track"
          stroke="currentColor"
          strokeWidth="0.75"
          fill="none"
          opacity="0.2"
        />

        {/* ── Transmission pulse dot ────────────────────────────────── */}
        <circle
          cx="88"
          cy="50"
          r="3"
          className="cipher-ring-pulse"
          fill="#59D8FF"
          opacity="0.6"
        />

        {/* ── Center mark — tiny refractive point ───────────────────── */}
        <circle
          cx="50"
          cy="50"
          r="1.5"
          fill="#59D8FF"
          opacity="0.5"
        />
      </svg>
    </div>
  );
}

/** Describe a circular arc path as SVG d-attribute. */
function describeRingPath(
  cx: number,
  cy: number,
  r: number,
  startAngle: number,
  sweepAngle: number,
): string {
  const toRad = (deg: number): number => (deg * Math.PI) / 180;

  const a1 = toRad(startAngle);
  const a2 = toRad(startAngle + sweepAngle);

  const x1 = cx + r * Math.cos(a1);
  const y1 = cy + r * Math.sin(a1);
  const x2 = cx + r * Math.cos(a2);
  const y2 = cy + r * Math.sin(a2);

  const largeArc = sweepAngle > 180 ? 1 : 0;
  const sweep = 1; // clockwise

  return `M ${x1.toFixed(1)} ${y1.toFixed(1)} A ${r} ${r} 0 ${largeArc} ${sweep} ${x2.toFixed(1)} ${y2.toFixed(1)}`;
}

export default CipherRing;
