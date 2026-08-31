"use client";

import { useEffect } from "react";
import Lenis from "lenis";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { useReducedMotion } from "@/lib/use-reduced-motion";

gsap.registerPlugin(ScrollTrigger);

/**
 * Lenis smooth-scroll physics, wired to GSAP's ticker so ScrollTrigger stays
 * in perfect sync with the eased scroll position. Disabled entirely under
 * `prefers-reduced-motion` — the page falls back to native scrolling and
 * ScrollTrigger reads the window directly.
 */
export function SmoothScroll({ children }: { children: React.ReactNode }) {
  const reduced = useReducedMotion();

  useEffect(() => {
    if (reduced) {
      // Reduced motion: no smoothing, but keep ScrollTrigger measuring native scroll.
      ScrollTrigger.refresh();
      return;
    }

    const lenis = new Lenis({
      duration: 1.1,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      smoothWheel: true,
      wheelMultiplier: 1,
      touchMultiplier: 1.4,
    });

    lenis.on("scroll", ScrollTrigger.update);

    const onTick = (time: number) => {
      lenis.raf(time * 1000);
    };
    gsap.ticker.add(onTick);
    gsap.ticker.lagSmoothing(0);

    // Let layout settle, then measure.
    const id = window.setTimeout(() => ScrollTrigger.refresh(), 200);

    return () => {
      window.clearTimeout(id);
      gsap.ticker.remove(onTick);
      lenis.destroy();
    };
  }, [reduced]);

  return <>{children}</>;
}
