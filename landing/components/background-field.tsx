"use client";

import { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import { WebMark } from "@/components/web-mark";
import { useReducedMotion } from "@/lib/use-reduced-motion";

// Lazy, no SSR — the WebGL scene must never block initial paint or LCP.
const ThreadScene = dynamic(() => import("@/components/thread-scene"), {
  ssr: false,
});

function hasWebGL(): boolean {
  try {
    const c = document.createElement("canvas");
    return !!(
      window.WebGLRenderingContext &&
      (c.getContext("webgl") || c.getContext("experimental-webgl"))
    );
  } catch {
    return false;
  }
}

type Mode = "pending" | "webgl" | "fallback";

export function BackgroundField() {
  const reduced = useReducedMotion();
  const [mode, setMode] = useState<Mode>("pending");

  useEffect(() => {
    if (reduced) {
      setMode("fallback");
      return;
    }
    // Full-fidelity WebGL on capable pointer-precise / wide viewports only;
    // everything else gets the identical SVG motif (see DESIGN.md §6).
    const wide = window.matchMedia("(min-width: 768px)").matches;
    const fine = window.matchMedia("(pointer: fine)").matches;
    const capable = hasWebGL() && (wide || fine);
    setMode(capable ? "webgl" : "fallback");
  }, [reduced]);

  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 overflow-hidden"
    >
      {mode === "webgl" ? (
        <ThreadScene />
      ) : (
        <div className="flex h-full w-full items-center justify-center">
          <WebMark
            className="h-[min(78vh,78vw)] w-[min(78vh,78vw)] opacity-[0.16]"
            spokes={10}
            rings={5}
          />
        </div>
      )}

      {/* Legibility scrims — quiet vignette so narrative copy always reads. */}
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(120% 90% at 50% 40%, transparent 55%, rgba(8,8,10,0.55) 100%)",
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
