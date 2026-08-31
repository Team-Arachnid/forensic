import * as React from "react";

/**
 * A parametric spider-web mark that echoes the Arachnid logo: concentric rings,
 * radial spokes, a small central hub, and three highlighted module nodes.
 *
 * This is the single motif rendered three ways across the site — as the
 * reduced-motion / no-WebGL fallback for the 3D field, and as the footer target
 * the animated threads resolve into. Pure SVG, no client JS required.
 */
type WebMarkProps = React.SVGProps<SVGSVGElement> & {
  spokes?: number;
  rings?: number;
  /** Emphasise the three module nodes in the accent colour. */
  showNodes?: boolean;
  title?: string;
};

const SIZE = 200;
const C = SIZE / 2;

function ring(radius: number, spokes: number): string {
  const pts: string[] = [];
  for (let i = 0; i < spokes; i++) {
    const a = (i / spokes) * Math.PI * 2 - Math.PI / 2;
    pts.push(`${(C + Math.cos(a) * radius).toFixed(2)},${(C + Math.sin(a) * radius).toFixed(2)}`);
  }
  return pts.join(" ");
}

export function WebMark({
  spokes = 8,
  rings = 4,
  showNodes = true,
  title,
  ...props
}: WebMarkProps) {
  const maxR = C - 8;
  const ringRadii = Array.from(
    { length: rings },
    (_, i) => maxR * ((i + 1) / rings),
  );

  // Three module nodes sit on the second-from-outer ring, spaced 120° apart.
  const nodeRing = ringRadii[rings - 2] ?? maxR * 0.7;
  const nodes = [0, 1, 2].map((i) => {
    const a = (i / 3) * Math.PI * 2 - Math.PI / 2;
    return {
      x: C + Math.cos(a) * nodeRing,
      y: C + Math.sin(a) * nodeRing,
    };
  });

  return (
    <svg
      viewBox={`0 0 ${SIZE} ${SIZE}`}
      fill="none"
      role={title ? "img" : "presentation"}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      {...props}
    >
      {title ? <title>{title}</title> : null}

      {/* outer double ring, as on the logo */}
      <circle cx={C} cy={C} r={maxR} stroke="var(--line)" strokeWidth="1" />
      <circle cx={C} cy={C} r={maxR - 5} stroke="var(--line)" strokeWidth="1" />

      {/* radial spokes */}
      {Array.from({ length: spokes }, (_, i) => {
        const a = (i / spokes) * Math.PI * 2 - Math.PI / 2;
        return (
          <line
            key={`spoke-${i}`}
            x1={C}
            y1={C}
            x2={C + Math.cos(a) * (maxR - 6)}
            y2={C + Math.sin(a) * (maxR - 6)}
            stroke="var(--line)"
            strokeWidth="1"
          />
        );
      })}

      {/* concentric web rings */}
      {ringRadii.slice(0, rings - 1).map((r, i) => (
        <polygon
          key={`ring-${i}`}
          points={ring(r, spokes)}
          stroke="var(--thread-dim)"
          strokeWidth="1"
        />
      ))}

      {/* the connecting thread between the three module nodes */}
      {showNodes && (
        <polygon
          points={nodes.map((n) => `${n.x.toFixed(2)},${n.y.toFixed(2)}`).join(" ")}
          stroke="var(--thread)"
          strokeWidth="1.5"
          opacity="0.85"
        />
      )}

      {/* central hub — the hex body echo */}
      <polygon points={ring(11, 6)} stroke="var(--thread)" strokeWidth="1.5" />

      {/* module nodes */}
      {showNodes &&
        nodes.map((n, i) => (
          <circle
            key={`node-${i}`}
            cx={n.x}
            cy={n.y}
            r="4"
            fill="var(--thread)"
            stroke="var(--void)"
            strokeWidth="1.5"
          />
        ))}
    </svg>
  );
}
