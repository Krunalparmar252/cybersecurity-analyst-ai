'use client';

import React, { useRef } from 'react';
import { gsap, useGSAP, prefersReducedMotion } from '@/lib/motion';

interface RevealProps {
  children: React.ReactNode;
  className?: string;
  delay?: number;
  duration?: number;
  direction?: 'up' | 'down' | 'fade';
  triggerOnce?: boolean;
}

export default function Reveal({
  children,
  className = '',
  delay = 0,
  duration = 0.6,
  direction = 'up',
  triggerOnce = true,
}: RevealProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useGSAP(
    () => {
      const el = containerRef.current;
      if (!el) return;

      if (prefersReducedMotion()) {
        gsap.set(el, { opacity: 1, y: 0 });
        return;
      }

      const initialY = direction === 'up' ? 24 : direction === 'down' ? -24 : 0;

      gsap.fromTo(
        el,
        {
          opacity: 0,
          y: initialY,
        },
        {
          opacity: 1,
          y: 0,
          duration,
          delay,
          ease: 'power2.out',
          scrollTrigger: {
            trigger: el,
            start: 'top 90%',
            once: triggerOnce,
          },
        }
      );
    },
    { scope: containerRef }
  );

  return (
    <div ref={containerRef} className={className}>
      {children}
    </div>
  );
}
