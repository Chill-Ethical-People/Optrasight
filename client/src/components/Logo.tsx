import { useId } from "react";

interface LogoProps {
  className?: string;
  size?: number;
  /** Disable gradient (mono / favicon contexts). Defaults to false. */
  mono?: boolean;
  /** Color override for the ring/horizon strokes. Defaults to currentColor. */
  ringColor?: string;
}

/**
 * OptraSight mark — observatory aperture + signal plane.
 *
 *  • faceted aperture boundary
 *  • signal sweep and protected core
 *  • horizon plane for evidence-led operations
 *
 * 84×84 native viewBox, scales perfectly from 16px favicon to 200px hero.
 */
export function Logo({
  className,
  size = 24,
  mono = false,
  ringColor,
}: LogoProps) {
  const rid = useId().replace(/:/g, "");
  const uid = `os-grad-${rid}`;
  const softUid = `os-soft-${rid}`;
  const stroke = ringColor ?? 'currentColor';

  const boundaryW = size <= 20 ? 4.8 : 2.6;
  const sweepW = size <= 20 ? 6.6 : 3.4;
  const detailW = size <= 24 ? 0 : 1.8;
  const dotR = size <= 20 ? 5.8 : 4.4;
  const dotInnerR = size <= 20 ? 2.3 : 1.9;

  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 84 84"
      fill="none"
      aria-label="OptraSight"
      role="img"
      xmlns="http://www.w3.org/2000/svg"
    >
      {!mono && (
        <defs>
          <linearGradient id={uid} x1="14" y1="16" x2="72" y2="70" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="hsl(var(--brand-2))" />
            <stop offset="58%" stopColor="hsl(var(--brand))" />
            <stop offset="100%" stopColor="hsl(var(--signal))" />
          </linearGradient>
          <radialGradient id={softUid} cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(43 42) rotate(90) scale(25)">
            <stop offset="0%" stopColor="hsl(var(--signal))" stopOpacity="0.22" />
            <stop offset="100%" stopColor="hsl(var(--signal))" stopOpacity="0" />
          </radialGradient>
        </defs>
      )}

      <path
        d="M42 6.5 66.5 16.6 77.5 42 66.5 67.4 42 77.5 17.5 67.4 6.5 42 17.5 16.6 42 6.5Z"
        stroke={stroke}
        strokeWidth={boundaryW}
        strokeLinejoin="round"
        strokeOpacity="0.86"
        fill={mono ? "none" : `url(#${softUid})`}
      />

      <path
        d="M24 55 C32 25 55 20 69 37"
        stroke={mono ? stroke : `url(#${uid})`}
        strokeWidth={sweepW}
        strokeLinecap="round"
        fill="none"
      />

      {detailW > 0 && (
        <>
          <path
            d="M17 42H67"
            stroke={stroke}
            strokeWidth={detailW}
            strokeOpacity="0.2"
            strokeLinecap="round"
          />
          <path
            d="M42 22 56 42 42 62 28 42 42 22Z"
            stroke={stroke}
            strokeWidth={detailW}
            strokeOpacity="0.34"
            strokeLinejoin="round"
            fill="none"
          />
        </>
      )}

      <circle
        cx="69"
        cy="37"
        r={dotR}
        fill={mono ? stroke : `url(#${uid})`}
      />
      {!mono && (
        <circle cx="69" cy="37" r={dotInnerR} fill="#ffffff" />
      )}
    </svg>
  );
}
