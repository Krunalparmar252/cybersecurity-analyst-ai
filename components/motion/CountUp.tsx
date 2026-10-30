'use client';

import React, { useRef, useState } from 'react';
import { gsap, useGSAP, prefersReducedMotion } from '@/lib/motion';

interface CountUpProps {
  end: number;
  start?: number;
  duration?: number;
  decimals?: number;
  suffix?: string;
  prefix?: string;
  className?: string;
}

export default function CountUp({
  end,
  start = 0,
  duration = 1.4,
  decimals = 0,
  suffix = '',
  prefix = '',
  className = '',
}: CountUpProps) {
  const [val, setVal] = useState(start);
  const containerRef = useRef<HTMLSpanElement>(null);

  useGSAP(
    () => {
      const el = containerRef.current;
      if (!el) return;

      if (prefersReducedMotion()) {
        setVal(end);
        return;
      }

      const counter = { value: start };

      gsap.to(counter, {
        value: end,
        duration,
        ease: 'power2.out',
        scrollTrigger: {
          trigger: el,
          start: 'top 90%',
          once: true,
        },
        onUpdate: () => {
          setVal(decimals > 0 ? parseFloat(counter.value.toFixed(decimals)) : Math.round(counter.value));
        },
      });
    },
    { scope: containerRef, dependencies: [end] }
  );

  return (
    <span ref={containerRef} className={`tabular-nums font-mono ${className}`}>
      {prefix}
      {decimals > 0 ? val.toFixed(decimals) : val}
      {suffix}
    </span>
  );
}

