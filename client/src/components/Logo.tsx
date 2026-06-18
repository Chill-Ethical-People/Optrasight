interface LogoProps {
  className?: string;
  size?: number;
  /** Kept for compatibility with older call sites; the smooth mark is always full-color. */
  mono?: boolean;
  /** Kept for compatibility with older call sites; the smooth mark is always full-color. */
  ringColor?: string;
}

const SMOOTH_MARK_SRC = `${import.meta.env.BASE_URL}brand/optrasight-smooth-mark-light-256.png`;

/** Shared OptraSight mark.
 *
 * The app uses the smooth transparent-core raster family from the brand kit so
 * login, shell chrome, setup, and browser assets stay visually consistent.
 */
export function Logo({ className, size = 24 }: LogoProps) {
  return (
    <img
      className={className}
      src={SMOOTH_MARK_SRC}
      alt="OptraSight"
      width={size}
      height={size}
      draggable={false}
      style={{
        width: size,
        height: size,
        objectFit: "contain",
      }}
    />
  );
}
