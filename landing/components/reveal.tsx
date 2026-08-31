"use client";

import { useEffect, useRef } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { useReducedMotion } from "@/lib/use-reduced-motion";

gsap.registerPlugin(ScrollTrigger);

type RevealProps = {
  children: React.ReactNode;
  className?: string;
  /** stagger seconds if wrapping multiple direct children */
  stagger?: number;
  delay?: number;
  y?: number;
  as?: "div" | "section" | "li" | "ul";
};

/**
 * Progressive scroll reveal. Content is fully visible with no JS (SSR renders
 * it normally); the fade/rise is applied only as an enhancement, and only when
 * motion is allowed. Under `prefers-reduced-motion` it is a no-op.
 */
export function Reveal({
  children,
  className,
  stagger = 0,
  delay = 0,
  y = 22,
  as = "div",
}: RevealProps) {
  const ref = useRef<HTMLElement>(null);
  const reduced = useReducedMotion();

  useEffect(() => {
    if (reduced || !ref.current) return;
    const el = ref.current;
    const targets = stagger ? Array.from(el.children) : el;

    const ctx = gsap.context(() => {
      gsap.fromTo(
        targets,
        { opacity: 0, y },
        {
          opacity: 1,
          y: 0,
          duration: 0.75,
          delay,
          ease: "power2.out",
          stagger: stagger || 0,
          scrollTrigger: {
            trigger: el,
            start: "top 86%",
            once: true,
          },
        },
      );
    }, el);

    return () => ctx.revert();
  }, [reduced, stagger, delay, y]);

  const Tag = as;
  return (
    <Tag ref={ref as never} className={className}>
      {children}
    </Tag>
  );
}
