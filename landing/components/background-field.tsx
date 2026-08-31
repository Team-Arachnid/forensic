import Image from "next/image";

/**
 * Site background: the Arachnid logo mark as a single large, faint watermark
 * fixed behind all content, with quiet vignette scrims so narrative copy stays
 * legible. Static and decorative — no WebGL, no scroll coupling.
 */
export function BackgroundField() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 overflow-hidden"
    >
      <div className="absolute inset-0 flex items-center justify-center">
        <Image
          src="/brand/mark.png"
          alt=""
          width={1000}
          height={1000}
          priority={false}
          className="h-auto w-[min(86vh,86vw)] max-w-none select-none opacity-[0.055]"
        />
      </div>

      {/* Legibility scrims — quiet vignette so copy always reads over the mark. */}
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(120% 92% at 50% 42%, transparent 50%, rgba(8,8,10,0.7) 100%)",
        }}
      />
      <div
        className="absolute inset-x-0 top-0 h-24"
        style={{
          background: "linear-gradient(to bottom, rgba(8,8,10,0.85), transparent)",
        }}
      />
    </div>
  );
}
