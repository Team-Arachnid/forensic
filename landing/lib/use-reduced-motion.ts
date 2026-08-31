"use client";

import { useEffect, useState } from "react";

/**
 * Tracks `prefers-reduced-motion: reduce`. Returns `true` when the user has
 * opted out of motion. SSR-safe: starts `false`, resolves on mount, and
 * updates live if the preference changes.
 */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(mq.matches);
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);

  return reduced;
}
